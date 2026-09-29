//! Standalone entry point for measuring extracted-tree hashing.
//! `cargo build --release --locked --example tree_hash`

#[path = "../src/core/tree.rs"]
#[allow(dead_code)]
mod tree;

fn main() -> anyhow::Result<()> {
    let dir = std::env::args_os().nth(1).expect("usage: tree_hash DIR");
    println!("{}", tree::tree_digest_of_dir(std::path::Path::new(&dir))?);
    Ok(())
}
