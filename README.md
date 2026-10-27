<!-- README.md -->

# Paryon (PUSD) Shielded Pool

Zero-knowledge privacy pool (zkSNARKs) for the **Paryon (PUSD)** stablecoin on BCH **Chipnet** — the core of
[nito.cash](https://github.com/APECSdev/nito.cash) **Private Payments**
(BCH Blaze 2026 submission).

**Status: live on chipnet.** The full pool lifecycle — deploy, SHIELD,
shielded→shielded TRANSFER, and UNSHIELD — is confirmed on-chain
(blocks [328733](https://chipnet.chaingraph.cash/tx/d3a442f3d3145cba3d1d6fd626164e077fa92b02720b882e3e98b40e70f4188c) / [328740](https://chipnet.chaingraph.cash/tx/3a8b9287ea97c050b0110522afa84daf0de90984ef3266db4062768d19adf8a5) / [328744](https://chipnet.chaingraph.cash/tx/c8d4c6e67859602a700b36ed33c6d90f0bf0ecb43c2e58b87041f845d4cc214a)).

**Latest redeploy (Option B):** the DEPLOY+SHIELD and TRANSFER were confirmed in the
**same block — 329722** ([`bd72f1f3…`](https://chipnet.imaginary.cash/tx/bd72f1f367cc5e6e8e9f485d84f308ae5e3f80e66b34f82998c7a38eb1698e1a) / [`b0a488db…`](https://chipnet.imaginary.cash/tx/b0a488db5b7e9bac07eebc45977523cd0730ddfe078571f2e17135231e30546b)), with the UNSHIELD confirmed in block **329736** ([`e90b9a56…`](https://chipnet.imaginary.cash/tx/e90b9a568d6908bf507e3239cde8b5ef055f9377aa95240d14453669f784717d)).

## Documentation

| File | Contents |
| ---- | -------- |
| `CHIPNET.md` | Build record + on-chain demo: deployment, the SHIELD / TRANSFER / UNSHIELD worked examples, verifier patching, trusted setup |
| `CIRCUIT-DESIGN.md` | The Circom / Groth16 joinsplit circuit (note commitments, nullifiers, Merkle tree) |
| `COVENANT-DESIGN.md` | The CashScript pool covenant (state machine, action-hash binding) |
| `GENERALIZED-SHIELDING.md` | Why "one assetCategory" is a deployment choice (not a circuit/contract limit) + the per-asset & multi-asset generalization paths |

## Main README

The **main project README** lives at
**[APECSdev/nito.cash](https://github.com/APECSdev/nito.cash)**.
