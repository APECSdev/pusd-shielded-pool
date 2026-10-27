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

**⚡ Multiple shielded transfers in ONE block.** Three chained shielded→shielded
**TRANSFERs** — each spending the previous transfer's pool output — were confirmed
together in a **single block,
[329433](https://chipnet.imaginary.cash/block/00000000000713585921eced7f7b48dd99862e3c5a51e03e08b110b80452fcfc)**
([`3d8faa40…`](https://chipnet.imaginary.cash/tx/3d8faa404c52c8ec22458e56d38f2d2af3c29e29bbfb68ed3821436851c1fcb9) · [`864c6c65…`](https://chipnet.imaginary.cash/tx/864c6c65fa361c20174642e46d9052d6be3a12deb5f50a367e7d2f1061dd82c3) · [`ea339140…`](https://chipnet.imaginary.cash/tx/ea3391409a0c09bf0d2f6858a1a537fcfbcc700e96a471be1f27a28514c84859),
each ~36.8 KB, no public value moved). Because a transfer spends the prior transfer's
pool output, many private payments can settle in the same block.

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
