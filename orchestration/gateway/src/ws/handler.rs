use axum::extract::ws::{Message, WebSocket};
use axum::extract::{State, WebSocketUpgrade};
use axum::response::IntoResponse;
use futures::SinkExt;
use futures::stream::StreamExt;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use tokio::sync::mpsc;

use crate::auth::ApiKeyId;
use crate::state::AppState;

const MAX_SUBSCRIPTIONS: usize = 10;
const HEARTBEAT_INTERVAL_SECS: u64 = 30;

/// Query params for WebSocket connection.
#[derive(Debug, Deserialize)]
pub struct WsQueryParams {
    pub request_ids: Option<String>,
}

/// Client -> Server messages.
#[derive(Debug, Deserialize)]
struct ClientMessage {
    action: String,
    request_id: Option<String>,
}

/// Server -> Client messages.
#[derive(Debug, Serialize)]
struct ServerMessage {
    #[serde(rename = "type")]
    msg_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    timestamp: Option<String>,
}

/// GET /v1/ws — WebSocket upgrade handler.
///
/// Requires API key via query param. Subscribes to NATS status updates
/// and forwards them to the connected client.
pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    api_key: ApiKeyId,
    axum::extract::Query(params): axum::extract::Query<WsQueryParams>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, state, api_key, params))
}

async fn handle_socket(
    socket: WebSocket,
    state: AppState,
    _api_key: ApiKeyId,
    params: WsQueryParams,
) {
    let (mut ws_sender, mut ws_receiver) = socket.split();
    let (tx, mut rx) = mpsc::channel::<Message>(100);

    // Track active subscriptions
    let mut subscribed: HashSet<String> = HashSet::new();

    // Parse initial request_ids from query params
    if let Some(ids) = &params.request_ids {
        for id in ids.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()) {
            if subscribed.len() >= MAX_SUBSCRIPTIONS {
                break;
            }
            subscribed.insert(id);
        }
    }

    // Spawn a task to forward messages from the channel to the WebSocket
    let send_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if ws_sender.send(msg).await.is_err() {
                break;
            }
        }
    });

    // Spawn NATS subscription tasks for initial subscriptions
    let cancel = tokio_util::sync::CancellationToken::new();

    for request_id in &subscribed {
        spawn_nats_subscription(&state, request_id, tx.clone(), cancel.clone());
        // Send subscription ack
        let ack = ServerMessage {
            msg_type: "subscribed".to_string(),
            request_id: Some(request_id.clone()),
            message: None,
            status: None,
            data: None,
            timestamp: None,
        };
        if let Ok(json) = serde_json::to_string(&ack) {
            let _ = tx.send(Message::Text(json.into())).await;
        }
    }

    // Spawn heartbeat
    let heartbeat_tx = tx.clone();
    let heartbeat_cancel = cancel.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(
            tokio::time::Duration::from_secs(HEARTBEAT_INTERVAL_SECS),
        );
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    if heartbeat_tx.send(Message::Ping(vec![].into())).await.is_err() {
                        break;
                    }
                }
                _ = heartbeat_cancel.cancelled() => break,
            }
        }
    });

    // Process incoming WebSocket messages
    while let Some(msg_result) = ws_receiver.next().await {
        match msg_result {
            Ok(Message::Text(text)) => {
                let parsed: Result<ClientMessage, _> = serde_json::from_str(&text);
                match parsed {
                    Ok(client_msg) => {
                        handle_client_message(
                            &client_msg,
                            &state,
                            &mut subscribed,
                            &tx,
                            &cancel,
                        )
                        .await;
                    }
                    Err(_) => {
                        let err = ServerMessage {
                            msg_type: "error".to_string(),
                            request_id: None,
                            message: Some("invalid_json".to_string()),
                            status: None,
                            data: None,
                            timestamp: None,
                        };
                        if let Ok(json) = serde_json::to_string(&err) {
                            let _ = tx.send(Message::Text(json.into())).await;
                        }
                    }
                }
            }
            Ok(Message::Close(_)) => break,
            Ok(Message::Pong(_)) => {} // heartbeat response, ignore
            Ok(_) => {}                // binary frames etc, ignore
            Err(_) => break,
        }
    }

    // Cleanup: cancel all NATS subscriptions
    cancel.cancel();
    send_task.abort();
}

async fn handle_client_message(
    msg: &ClientMessage,
    state: &AppState,
    subscribed: &mut HashSet<String>,
    tx: &mpsc::Sender<Message>,
    cancel: &tokio_util::sync::CancellationToken,
) {
    match msg.action.as_str() {
        "subscribe" => {
            let Some(ref request_id) = msg.request_id else {
                send_error(tx, "request_id required for subscribe").await;
                return;
            };

            if !is_valid_request_id(request_id) {
                send_error(tx, "invalid_request_id").await;
                return;
            }

            if subscribed.len() >= MAX_SUBSCRIPTIONS {
                send_error(tx, "max_subscriptions_exceeded").await;
                return;
            }

            if subscribed.insert(request_id.clone()) {
                spawn_nats_subscription(state, request_id, tx.clone(), cancel.clone());
            }

            let ack = ServerMessage {
                msg_type: "subscribed".to_string(),
                request_id: Some(request_id.clone()),
                message: None,
                status: None,
                data: None,
                timestamp: None,
            };
            if let Ok(json) = serde_json::to_string(&ack) {
                let _ = tx.send(Message::Text(json.into())).await;
            }
        }
        "unsubscribe" => {
            let Some(ref request_id) = msg.request_id else {
                send_error(tx, "request_id required for unsubscribe").await;
                return;
            };

            subscribed.remove(request_id);

            let ack = ServerMessage {
                msg_type: "unsubscribed".to_string(),
                request_id: Some(request_id.clone()),
                message: None,
                status: None,
                data: None,
                timestamp: None,
            };
            if let Ok(json) = serde_json::to_string(&ack) {
                let _ = tx.send(Message::Text(json.into())).await;
            }
        }
        _ => {
            send_error(tx, "unknown_action").await;
        }
    }
}

fn spawn_nats_subscription(
    state: &AppState,
    request_id: &str,
    tx: mpsc::Sender<Message>,
    cancel: tokio_util::sync::CancellationToken,
) {
    let subject = format!("sincerin.proofs.status.{request_id}");
    let js = state.jetstream.clone();
    let rid = request_id.to_string();

    tokio::spawn(async move {
        // Subscribe to the NATS subject for this request_id
        let sub = match js.get_stream("PROOF_STATUS").await {
            Ok(stream) => {
                let inbox = format!("_INBOX.ws.{}", uuid::Uuid::new_v4().simple());
                let consumer_config = async_nats::jetstream::consumer::push::Config {
                    deliver_subject: inbox,
                    filter_subject: subject.clone(),
                    deliver_policy: async_nats::jetstream::consumer::DeliverPolicy::New,
                    ..Default::default()
                };
                match stream.create_consumer(consumer_config).await {
                    Ok(consumer) => Some(consumer),
                    Err(e) => {
                        tracing::warn!("Failed to create NATS consumer for {subject}: {e}");
                        None
                    }
                }
            }
            Err(e) => {
                tracing::warn!("Failed to get PROOF_STATUS stream: {e}");
                None
            }
        };

        if let Some(consumer) = sub {
            let mut messages = match consumer.messages().await {
                Ok(m) => m,
                Err(_) => return,
            };

            loop {
                tokio::select! {
                    msg = messages.next() => {
                        match msg {
                            Some(Ok(nats_msg)) => {
                                let update = ServerMessage {
                                    msg_type: "status_update".to_string(),
                                    request_id: Some(rid.clone()),
                                    message: None,
                                    status: None,
                                    data: serde_json::from_slice(&nats_msg.payload).ok(),
                                    timestamp: Some(chrono::Utc::now().to_rfc3339()),
                                };
                                if let Ok(json) = serde_json::to_string(&update)
                                    && tx.send(Message::Text(json.into())).await.is_err()
                                {
                                    break;
                                }
                                let _ = nats_msg.ack().await;
                            }
                            Some(Err(_)) => break,
                            None => break,
                        }
                    }
                    _ = cancel.cancelled() => break,
                }
            }
        }
    });
}

fn is_valid_request_id(id: &str) -> bool {
    id.len() == 66 && id.starts_with("0x") && id[2..].chars().all(|c| c.is_ascii_hexdigit())
}

async fn send_error(tx: &mpsc::Sender<Message>, message: &str) {
    let err = ServerMessage {
        msg_type: "error".to_string(),
        request_id: None,
        message: Some(message.to_string()),
        status: None,
        data: None,
        timestamp: None,
    };
    if let Ok(json) = serde_json::to_string(&err) {
        let _ = tx.send(Message::Text(json.into())).await;
    }
}
