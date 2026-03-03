use std::path::PathBuf;
use std::process::Stdio;
use std::time::Instant;

use async_trait::async_trait;
use flate2::write::GzEncoder;
use flate2::Compression;
use std::io::Write;
use tracing::{info, warn};

use crate::backends::{ProofOutput, ProverBackend};
use crate::errors::ProverError;

/// Barretenberg CLI backend for UltraHonk proof generation.
///
/// Invokes the `bb` CLI binary as a subprocess to generate and verify
/// proofs. Manages temporary files for witness input and proof output.
#[derive(Debug)]
pub struct BarretenbergBackend {
    bb_binary_path: PathBuf,
    circuits_dir: PathBuf,
    work_dir: PathBuf,
}

/// Magic bytes for gzip format detection.
const GZIP_MAGIC: [u8; 2] = [0x1f, 0x8b];

impl BarretenbergBackend {
    /// Create a new backend, validating that required paths exist.
    pub fn new(
        bb_binary_path: PathBuf,
        circuits_dir: PathBuf,
        work_dir: PathBuf,
    ) -> Result<Self, ProverError> {
        if !bb_binary_path.exists() {
            return Err(ProverError::BbNotFound(
                bb_binary_path.display().to_string(),
            ));
        }
        if !circuits_dir.is_dir() {
            return Err(ProverError::CircuitNotFound(format!(
                "circuits directory not found: {}",
                circuits_dir.display()
            )));
        }
        std::fs::create_dir_all(&work_dir)?;

        Ok(Self {
            bb_binary_path,
            circuits_dir,
            work_dir,
        })
    }

    /// Resolve the ACIR circuit bytecode path for a given circuit ID.
    fn get_circuit_path(&self, circuit_id: &str) -> Result<PathBuf, ProverError> {
        let path = self
            .circuits_dir
            .join(circuit_id)
            .join("target")
            .join("circuit.json");
        if !path.exists() {
            return Err(ProverError::CircuitNotFound(circuit_id.to_string()));
        }
        Ok(path)
    }

    /// Resolve the verification key path for a given circuit ID.
    fn get_vk_path(&self, circuit_id: &str) -> Result<PathBuf, ProverError> {
        let path = self
            .circuits_dir
            .join(circuit_id)
            .join("target")
            .join("vk");
        if !path.exists() {
            return Err(ProverError::CircuitNotFound(format!(
                "{circuit_id}/target/vk"
            )));
        }
        Ok(path)
    }

    /// Ensure witness bytes are gzip-compressed.
    /// If already compressed (detected via magic bytes), returns as-is.
    fn ensure_gzipped(witness: &[u8]) -> Result<Vec<u8>, ProverError> {
        if witness.is_empty() {
            return Err(ProverError::EmptyWitness);
        }

        if witness.len() >= 2 && witness[..2] == GZIP_MAGIC {
            // Already gzip-compressed
            return Ok(witness.to_vec());
        }

        // Compress the witness
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(witness)?;
        let compressed = encoder.finish()?;
        Ok(compressed)
    }
}

#[async_trait]
impl ProverBackend for BarretenbergBackend {
    async fn prove(&self, circuit_id: &str, witness: &[u8]) -> Result<ProofOutput, ProverError> {
        let circuit_path = self.get_circuit_path(circuit_id)?;

        // Create a temp directory for this proof invocation
        let temp_dir = tempfile::tempdir_in(&self.work_dir)?;
        let witness_path = temp_dir.path().join("witness.gz");
        let proof_path = temp_dir.path().join("proof");

        // Write witness (ensure gzipped)
        let compressed = Self::ensure_gzipped(witness)?;
        tokio::fs::write(&witness_path, &compressed).await?;

        info!(
            circuit_id = circuit_id,
            witness_size = compressed.len(),
            "Starting proof generation via bb CLI"
        );

        let start = Instant::now();

        let output = tokio::process::Command::new(&self.bb_binary_path)
            .arg("prove")
            .arg("-i")
            .arg(&witness_path)
            .arg("-b")
            .arg(&circuit_path)
            .arg("-o")
            .arg(&proof_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await?;

        let proving_time_ms = start.elapsed().as_millis() as u64;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!(
                circuit_id = circuit_id,
                exit_code = ?output.status.code(),
                stderr = %stderr,
                "bb prove failed"
            );
            return Err(ProverError::ProveFailed(stderr.to_string()));
        }

        let proof = tokio::fs::read(&proof_path).await?;

        info!(
            circuit_id = circuit_id,
            proof_size = proof.len(),
            proving_time_ms = proving_time_ms,
            "Proof generated successfully"
        );

        metrics::counter!("sincerin_prover_proofs_generated_total",
            "circuit_id" => circuit_id.to_string(),
            "status" => "success"
        )
        .increment(1);

        metrics::histogram!("sincerin_prover_proof_generation_ms",
            "circuit_id" => circuit_id.to_string()
        )
        .record(proving_time_ms as f64);

        // temp_dir is cleaned up automatically on drop
        Ok(ProofOutput {
            proof,
            proving_time_ms,
        })
    }

    async fn verify(&self, circuit_id: &str, proof: &[u8]) -> Result<bool, ProverError> {
        let vk_path = self.get_vk_path(circuit_id)?;

        let temp_dir = tempfile::tempdir_in(&self.work_dir)?;
        let proof_path = temp_dir.path().join("proof");

        tokio::fs::write(&proof_path, proof).await?;

        info!(circuit_id = circuit_id, "Verifying proof via bb CLI");

        let output = tokio::process::Command::new(&self.bb_binary_path)
            .arg("verify")
            .arg("-k")
            .arg(&vk_path)
            .arg("-p")
            .arg(&proof_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await?;

        if output.status.success() {
            info!(circuit_id = circuit_id, "Proof verified successfully");
            Ok(true)
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!(
                circuit_id = circuit_id,
                stderr = %stderr,
                "Proof verification failed"
            );
            Ok(false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_invalid_bb_path() {
        let result = BarretenbergBackend::new(
            PathBuf::from("/nonexistent/bb"),
            PathBuf::from("."),
            PathBuf::from("/tmp/test-prover"),
        );
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("bb binary not found"),
            "Expected 'bb binary not found', got: {err}"
        );
    }

    #[test]
    fn test_new_invalid_circuits_dir() {
        // Use a real bb path or skip if not available
        let bb_path = PathBuf::from("/tmp/bb");
        if !bb_path.exists() {
            return; // Skip test if bb not installed
        }
        let result = BarretenbergBackend::new(
            bb_path,
            PathBuf::from("/nonexistent/circuits"),
            PathBuf::from("/tmp/test-prover"),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_ensure_gzipped_already_compressed() {
        // Create a minimal gzip header
        let mut data = vec![0x1f, 0x8b, 0x08, 0x00]; // gzip magic + flags
        data.extend_from_slice(&[0; 10]); // rest of header
        let result = BarretenbergBackend::ensure_gzipped(&data).unwrap();
        assert_eq!(result, data, "Already compressed data should pass through");
    }

    #[test]
    fn test_ensure_gzipped_compresses_raw() {
        let raw = b"hello witness data";
        let result = BarretenbergBackend::ensure_gzipped(raw).unwrap();
        assert!(
            result.len() >= 2 && result[..2] == GZIP_MAGIC,
            "Result should be gzip-compressed"
        );
    }

    #[test]
    fn test_ensure_gzipped_empty_witness() {
        let result = BarretenbergBackend::ensure_gzipped(&[]);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Empty witness"));
    }
}
