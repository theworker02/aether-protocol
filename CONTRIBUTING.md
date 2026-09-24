# Contributing

Thanks for helping improve Aether Protocol.

## Development setup

```bash
rustup update stable
cargo build -p aether-node -p aether-cli
cargo test -p aether-zk --lib
cd apps/explorer && npm install && npm run build
```

## Branch & PR hygiene

1. Open an issue for substantial design changes.  
2. Keep PRs focused (one concern per PR).  
3. Update docs when changing wire formats or genesis fields.  
4. Add/adjust unit tests for ZK, state transitions, and config parsing.  
5. Do not commit secrets (`validator.key`, production `zk_keys.json`).

## Code style

- Rust: `cargo fmt`, `cargo clippy -p aether-node -- -D warnings` when possible  
- Prefer small crates and explicit domain-separated crypto tags  
- Document adapter traits in `docs/ADAPTING.md` when adding extension points  

## Spec vs implementation

Normative behavior lives in `docs/*.md`. If code and docs diverge, **fix the docs in the same PR** or mark the code path `experimental`.

## License

Contributions are accepted under Apache-2.0.
