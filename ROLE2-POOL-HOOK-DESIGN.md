# ROLE2-POOL-HOOK-DESIGN.md — putting the pool rules into the sound verifier's third role

**Status: DESIGN (2026-11-24). Not implemented, not reviewed, not deployed.**
This document exists because the code that follows it is *new bytes nobody has reviewed*, which is
exactly how finding F6 and the v2 layout bug happened. The design is the reviewable artifact.

---

## 1. Why role 2, and not a sibling covenant

Two independent measurements rule out the sibling composition:

- **From the covenant side** (`pin-sibling-test.mjs`, 6/6 on the BCH-2026 VM): the deployed
  covenant read the genesis sibling's unlocking at fixed offsets and never checked that input's
  locking, so a one-byte `OP_1` at that index was **accepted**.
- **From the verifier side** (red team under our VK, 151 runs / 0 accepted): the sound verifier's
  graph pins `TXINPUTCOUNT == 3` and `UTXOBYTECODE(j) == UTXOBYTECODE(OP_INPUTINDEX)` for every j.
  All three "foreign P2SH32 input at index *j* carrying the honest pushes" runs **reject**.

So the two cannot be composed as siblings in either direction. The sound verifier's own README
names the intended integration: *"Outputs are unconstrained: applications that release funds add
output rules in role 2."*

## 2. The hook already exists

`chunked/bn254/bn-native-sound/script.mjs:258`:

```js
if (last && COVENANT) { a.mark('covenant'); COVENANT(a); } // Track 11 (real-keys/covenant.mjs):
                                                            // application binding of n0, n1; off by default
```

and `chunked/bn254/real-keys/covenant.mjs` is a **worked example of the hook for two real systems**
(SP1 v5 and RISC Zero), registered with `setCovenant` from `script.mjs`. Its documented contract:

> The plain verifier proves "(A, B, C, n0, n1) satisfies Groth16 for the baked VK" for whatever n0,
> n1 the prover writes into STMT. A covenant that RELEASES value must say which statement it
> accepts: it must derive n0 and n1 itself, from constants in its code and from transaction data,
> and require that the decoded n0, n1 equal them. This module adds exactly that to role 2 (the role
> that owns STMT and runs the binding) … right after STMT is decoded and range-checked (< r).

The hook runs with `n0` and `n1` on the stack as **named items**, so it can `a.pick('n0', …)` and
`a.pick('n1', …)` and compare. The transaction's outputs are supplied to the harness by
`setOutputs` from `bn-native-sound/vm.mjs`.

That means A is not "write a role-2 program". It is "write one hook, following an existing
example, and price it with the existing cost harness".

## 3. Where the pool's transition data comes from

The pool needs eight 32-byte values to rebuild the actionHash:

```
nf0 ‖ nf1 ‖ cm0 ‖ cm1 ‖ publicValueAbs ‖ publicValueSign ‖ assetCategory ‖ newMerkleRoot   (256 B)
```

The worked example already answers where application data lives: **SP1's public values and RISC
Zero's journal are carried by the transaction, in output 0's OP_RETURN, and bound by hashing into
n1.** We do the same, with one change — the 256-byte block is larger than a standard OP_RETURN
allows (223 B), so the carrier is **output 0 as a plain P2SH32-free data output**, read with
`OP_0 OP_OUTPUTBYTECODE`, with an exact length and prefix check.

**Why carrying the data in an output is sound.** The prover may write anything into that output.
They may not change it without changing `n1`, because `n1` is defined as the digest of exactly
those bytes — and `n1` is bound to the proof by the GT-GLS fold (`vk_x = IC0 + n0·IC1 + n1·IC2`)
that role 2 already enforces. So the carrier is a *convenience*, not a trust anchor: the anchor is
the same `n1` binding the verifier already has.

## 4. Where the pool state lives

The three verifier inputs all spend `P2SH32(R)`. The pool's mutable state NFT therefore rides on
**input 2 — role 2's own input** — so `this.activeInputIndex` inside role 2 *is* the state input:

| field | meaning |
|---|---|
| `tx.inputs[2].tokenCategory` | must equal `assetCategory + 0x01` (mutable NFT of the pool category) |
| `tx.inputs[2].nftCommitment` | `merkleRoot[32] ‖ nullifierSetHash[32]` — the stored state |
| `tx.inputs[2].tokenAmount` | the pool's FT balance |

Consequence: **one of the three verifier UTXOs is the pool's continuity UTXO.** The pool is not a
separate covenant beside the verifier; the pool *is* the verifier's third input. That is a real
architectural change from the current 7-input layout and it needs stating plainly.

## 5. The checks the hook must add

Mapped from `asset-pool.cash` (the deployed covenant) into the hook:

| # | check | opcode path |
|---|---|---|
| 1 | `tx.version == 2` | `OP_TXVERSION OP_2 OP_NUMEQUALVERIFY` |
| 2 | input 2 carries `category + 0x01` | `OP_INPUTINDEX OP_UTXOTOKENCATEGORY` vs a ctor-pinned `C‖01` |
| 3 | carrier output: exact size + prefix | `OP_0 OP_OUTPUTBYTECODE OP_SIZE` / `OP_SPLIT` |
| 4 | decode the eight limbs, each `< r` | `OP_BIN2NUM` + range (the verifier already range-checks n0/n1; these are new) |
| 5 | `n0 == commitment[0..32]` (stored root) | `OP_INPUTINDEX OP_UTXOTOKENCOMMITMENT OP_SPLIT(32)` |
| 6 | `n1 == SHA256(preimage) & (2^253 − 1)`, LE | 7 × `OP_CAT` + `OP_SHA256` + mask + `OP_REVERSEBYTES` |
| 7 | `newNullHash == SHA256(oldNullHash ‖ nf0 ‖ nf1)` | 2 × `OP_CAT` + `OP_SHA256` |
| 8 | `newBalance == balance + pv − 2·sign·pv`, `≥ 0` | `OP_MUL`/`OP_ADD`/`OP_SUB`/`OP_WITHIN` |
| 9 | out0 locking == input 2 locking | `OP_0 OP_OUTPUTBYTECODE` vs `OP_INPUTINDEX OP_UTXOBYTECODE` |
| 10 | out0 category == `C‖01`, commitment == `newRoot ‖ newNullHash`, amount == `newBalance` | 3 introspection reads |
| 11 | if `sign == 1`: a payout output of `pv` at category `C` | `OP_OUTPUTTOKENCATEGORY` / `OP_OUTPUTTOKENAMOUNT` |

Checks 5 and 6 are the ones that make the proof mean something: 5 anchors the proof to *this pool's
current root*, 6 forces the proof to attest to *exactly this transition*. Everything else is
bookkeeping that the old covenant already did.

## 6. Budget

Role 2's per-input budget is `(41 + unlockingLength) × 800`. Measured on our build
(`SOUND-VERIFIER-BUILD.md`): unlocking 8,748 B → budget 7,031,200; op 6,574,203 → **≈ 457k spare**
(6.5% consensus margin). The old covenant's whole `spend()` cost 84,819 op in Gate 6 with a real
witness; the hook is a subset of that logic plus one SHA256 over 256 B.

So the arithmetic says it fits with room. **That is an estimate, not a measurement** — the number
that counts comes from `chunked/bn254/pinned/covenant-cost.mjs`, which prices a hook as the
*difference* between the templated build and the plain build over the same proof and statement,
in both standard and consensus mode. That harness must be re-pointed at our hook.

## 7. What must happen before this carries value

1. **Implement** the hook as `pool-hook.mjs`, registered with `setCovenant`; follow
   `real-keys/covenant.mjs` structure and naming.
2. **Measure** with the `covenant-cost.mjs` difference method; if the margin drops below the
   design buffer, the filler sizing must be re-run (`sizeFills`).
3. **Re-run the red team** (`export-our.mjs` + `redteam.mjs`) — the hook's own rejections are not
   in the shipped suite and must be written: wrong category, wrong stored root, tampered carrier,
   tampered nullifier fold, wrong new balance, out0 to a foreign locking, missing payout.
4. **Get it reviewed.** New bytes at a supported extension point are still new bytes.
5. **Redeploy** — one deploy, with the pinned covenant logic now *inside* the verifier rather than
   beside it.

## 8. Open questions this design does not answer

- **Where the three verifier UTXOs come from per action.** Today they are five funded step UTXOs
  recreated in program order. With the state on input 2, the pool needs a supply of fresh exec0 /
  exec1 UTXOs and a state UTXO. The economics of that (who funds them, how they are replenished)
  is a wallet-layer question, not a script question.
- **Whether `tx.inputs[2]` is the right slot** versus making the state input explicit in the graph.
  Using role 2's own index is the smallest change; making it explicit would need a graph change,
  which is reviewed code.
- **The unshield payout index.** The old covenant used output 1. With output 0 now the new state,
  the payout is output 1 — but that must be pinned, not assumed, because outputs are otherwise
  unconstrained.
- **Whether the nullifier set needs to move on-chain.** The old covenant folds `nf0`, `nf1` into a
  rolling SHA256 and leaves the full set to an indexer. That is unchanged by this design, and it
  remains the weakest part of the pool's double-spend story: the *set* is off-chain, only its
  rolling hash is on-chain.
