use axum::Json;
use axum::extract::State;
use serde::Serialize;

use crate::state::AppState;

#[derive(Serialize)]
pub struct CircuitInfo {
    pub id: String,
    pub name: String,
    pub description: String,
    pub proof_system: String,
    pub estimated_constraints: u64,
    pub client_side_feasible: bool,
    pub estimated_time_ms: u64,
}

#[derive(Serialize)]
pub struct CircuitsResponse {
    pub circuits: Vec<CircuitInfo>,
}

pub async fn list_circuits(State(state): State<AppState>) -> Json<CircuitsResponse> {
    // MVP: hardcoded circuit registry
    let circuits: Vec<CircuitInfo> = state
        .valid_circuits
        .iter()
        .map(|id| match id.as_str() {
            "proof-of-membership" => CircuitInfo {
                id: "proof-of-membership".to_string(),
                name: "Proof of Membership".to_string(),
                description: "Prove membership in a Merkle tree without revealing position"
                    .to_string(),
                proof_system: "ultra_honk".to_string(),
                estimated_constraints: 20_000,
                client_side_feasible: true,
                estimated_time_ms: 3000,
            },
            "proof-of-age" => CircuitInfo {
                id: "proof-of-age".to_string(),
                name: "Proof of Age".to_string(),
                description: "Prove age threshold without revealing birthdate".to_string(),
                proof_system: "ultra_honk".to_string(),
                estimated_constraints: 50_000,
                client_side_feasible: true,
                estimated_time_ms: 5000,
            },
            _ => CircuitInfo {
                id: id.clone(),
                name: id.clone(),
                description: "Custom circuit".to_string(),
                proof_system: "ultra_honk".to_string(),
                estimated_constraints: 0,
                client_side_feasible: false,
                estimated_time_ms: 10000,
            },
        })
        .collect();

    Json(CircuitsResponse { circuits })
}
