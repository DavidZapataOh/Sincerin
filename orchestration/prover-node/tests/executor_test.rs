mod helpers;

use sincerin_common::types::PrivacyStrategy;
use sincerin_prover_node::executor::Executor;

#[tokio::test]
async fn test_executor_direct_delegation_with_mock() {
    let backend = helpers::mock_backend_success();
    let executor = Executor::new(backend, "prover-test".to_string());

    let task = helpers::make_prover_task(
        "exec-dd-001",
        "proof-of-membership",
        PrivacyStrategy::DirectDelegation,
        Some(vec![1, 2, 3, 4]),
    );

    let result = executor.execute(&task).await.unwrap();
    assert_eq!(result.request_id, "exec-dd-001");
    assert_eq!(result.circuit_id, "proof-of-membership");
    assert_eq!(result.proof, vec![0xde, 0xad, 0xbe, 0xef]);
    assert_eq!(result.proving_time_ms, 1500);
    assert_eq!(result.prover_id, "prover-test");
    assert_eq!(
        result.privacy_strategy,
        PrivacyStrategy::DirectDelegation
    );
}

#[tokio::test]
async fn test_executor_missing_witness_error() {
    let backend = helpers::mock_backend_success();
    let executor = Executor::new(backend, "prover-test".to_string());

    let task = helpers::make_prover_task(
        "exec-mw-001",
        "proof-of-membership",
        PrivacyStrategy::DirectDelegation,
        None, // No witness
    );

    let err = executor.execute(&task).await.unwrap_err();
    assert!(err.to_string().contains("Missing witness"));
}

#[tokio::test]
async fn test_executor_client_side_rejected() {
    let backend = helpers::mock_backend_success();
    let executor = Executor::new(backend, "prover-test".to_string());

    let task = helpers::make_prover_task(
        "exec-cs-001",
        "proof-of-membership",
        PrivacyStrategy::ClientSide,
        None,
    );

    let err = executor.execute(&task).await.unwrap_err();
    assert!(err.to_string().contains("client-side"));
}

#[tokio::test]
async fn test_executor_structural_split_unsupported() {
    let backend = helpers::mock_backend_success();
    let executor = Executor::new(backend, "prover-test".to_string());

    let task = helpers::make_prover_task(
        "exec-ss-001",
        "proof-of-membership",
        PrivacyStrategy::StructuralSplit,
        None,
    );

    let err = executor.execute(&task).await.unwrap_err();
    assert!(err.to_string().contains("StructuralSplit"));
}

#[tokio::test]
async fn test_executor_backend_failure_propagates() {
    let backend = helpers::mock_backend_failure();
    let executor = Executor::new(backend, "prover-test".to_string());

    let task = helpers::make_prover_task(
        "exec-fail-001",
        "proof-of-membership",
        PrivacyStrategy::DirectDelegation,
        Some(vec![1, 2, 3]),
    );

    let err = executor.execute(&task).await.unwrap_err();
    assert!(err.to_string().contains("mock failure"));
}

#[tokio::test]
async fn test_executor_result_fields_populated() {
    let backend = helpers::mock_backend_success();
    let executor = Executor::new(backend, "prover-test".to_string());

    let task = helpers::make_prover_task(
        "exec-fields-001",
        "proof-of-age",
        PrivacyStrategy::DirectDelegation,
        Some(vec![10, 20, 30]),
    );

    let result = executor.execute(&task).await.unwrap();
    assert_eq!(result.request_id, "exec-fields-001");
    assert_eq!(result.circuit_id, "proof-of-age");
    assert!(!result.proof_id.is_empty());
    assert!(result.created_at > 0);
    assert!(!result.verified); // L1 verification happens in collector
    assert_eq!(result.verification_gas, 0);
    assert!(result.l1_tx_hash.is_none());
}

#[tokio::test]
async fn test_executor_emsm_strategy_unsupported() {
    let backend = helpers::mock_backend_success();
    let executor = Executor::new(backend, "prover-test".to_string());

    let task = helpers::make_prover_task(
        "exec-emsm-001",
        "proof-of-membership",
        PrivacyStrategy::Emsm,
        None,
    );

    let err = executor.execute(&task).await.unwrap_err();
    assert!(err.to_string().contains("Emsm"));
}
