/// Re-export the PDF utility module so its `#[cfg(test)]` tests are
/// reachable via `cargo test --lib`.
pub mod pdf_utils;
