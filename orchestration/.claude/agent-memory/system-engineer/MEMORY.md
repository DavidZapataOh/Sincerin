# System Engineer Memory (Orchestration)

## Rust Toolchain
- Cargo at `/Users/david/.cargo/bin/cargo` -- absolute path required in agent Bash calls
- Rust 1.93.1, edition 2024

## Alloy Crate API (resolved to v1.7.3)
- Workspace declares `alloy = "0.9"` but semver resolves to **1.7.3** (no lock file pin).
- `RootProvider` in v1.x: single generic `RootProvider<N: Network = Ethereum>` (no transport generic).
- Use `RootProvider::new_http(url)` for bare provider. `ProviderBuilder::new().connect_http()` returns `FillProvider`, not `RootProvider`.
- URL type: `alloy::transports::http::reqwest::Url`.
- `sol!` + `#[sol(rpc)]`: single-return view functions yield value directly (no `._0`). Multi-return generates named struct.
- Contract: `IFoo::new(address, &provider)` takes provider reference. View: `.call().await?`. Write: `.send().await?.watch().await?`.

## Known Issues
- `std::env::set_var`/`remove_var` are **unsafe** in edition 2024. Wrap with `unsafe {}`.
- bincode 1.x cannot deserialize `serde_json::Value` (no `deserialize_any` support) -- use JSON-then-bincode envelope
- Module-level doc comments must use `//!` (inner doc), not `///` (outer doc), to avoid clippy `empty_line_after_doc_comments`.

## Config Crate (v0.14)
- Do NOT use `separator("_")` with `Environment::with_prefix("SINCERIN")` for flat structs -- splits `SINCERIN_COORDINATOR_ADDRESS` into nested `coordinator.address`. Use `try_parsing(true)` instead.
- Config tests use `static ENV_MUTEX: Mutex<()>` with `unwrap_or_else(|e| e.into_inner())` to handle mutex poisoning.

## Types Module
- PrivacyStrategy variants: ClientSide, StructuralSplit, Emsm, CoSnark, TeeIsolated, DirectDelegation
- PrivacyLevel variants: Mandatory, Preferred, None
- ProofStatus: internally tagged enum (`#[serde(tag = "state")]`)
- All enums: `#[serde(rename_all = "snake_case")]`

## Common Crate Module Status (29 passing, 3 ignored, 0 clippy warnings)
- `types/` (19 tests) | `nats.rs` (1+2 ignored) | `l1_client.rs` (3+1 ignored)
- `metrics.rs` (2 tests) | `errors.rs` (2 tests) | `config.rs` (2 tests)
