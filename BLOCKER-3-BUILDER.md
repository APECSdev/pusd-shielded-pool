# Blocker 3 — the wallet-side covenant transaction builder: state + findings

**Status (2026-11-22): the builder is implemented and verified for everything the
wallet controls. The one open item is runner-gated: the ALREADY-DEPLOYED pools'
verifier-step witness algorithm is a bench worktree revision that is not in the
public repo, so the wallet cannot regenerate THEIR five verifier inputs until the
runner's exact worktree is recovered (runner returns 2026-11-24+).**

The wallet implementation (nito.cash `apps/web/src/lib/pool/`):

| Piece | File | Verification |
| ----- | ---- | ------------ |
| Verifier-step witness port (produceWitness + msmWitness + assembly) | `verifier.js` | **BYTE-EXACT** vs the bench's own `produceTransaction` output: all five unlockings reproduce `artifacts/verifier-vectors.json` byte-for-byte for the generating fixture (real proof over the older vkey). Also accepts snarkjs `{pi_a,pi_b,pi_c}` proofs (the wallet prover's format). |
| Deployed program constants (step redeems, shared fragments, lockings) | `verifier-program.js` | Extracted byte-for-byte from the live chipnet actions; **byte-identical across all 7 live actions** (6 Option B + gate3 SHIELD) — one deployed program. |
| Covenant tx builder (SHIELD/TRANSFER/UNSHIELD assembly + funding signing) | `build.js` | Covenant unlocking **byte-exact** vs the live gate3 SHIELD; full-tx decode round-trip; root binding; token conservation; Schnorr funding sigs. |
| Registry | `registry.js` | `covenantRedeem` per pool (the deployed 347 B redeem, hash-verified against the P2SH32 locking). |

## VM-eval results (apecsdev VM, BCH 2026 VM, `createVirtualMachineBch2026(true)`)

A wallet-built full SHIELD tx (synthetic 2469acc5-category covenant + the REAL eval
shield proof + carrier output + token-bearing funding inputs):

```
in[0] covenant  : ACCEPTED   (opCost 73,818 / 448,800)   ← deployed redeem logic,
                  carrier tolerance, actionHash binding, root binding, conservation
in[6] funding   : ACCEPTED   (Schnorr SIGHASH_ALL|FORKID, token-bearing source outputs)
in[7] funding   : ACCEPTED
in[1..5] steps  : rejected   ← see below
```

Control experiment: the LIVE b0a488db TRANSFER's five on-chain verifier inputs
**ACCEPT** in the same harness — the harness, source-output setup and deployed
redeems are all correct; the rejection isolates to the witness values.

## The discovery: the deployed program is a different bench generation

1. The deployed exec redeems differ from the local (bench main) redeems in 43
   bytes — all CONSTANTS: the embedded fragment-length locators (exec2 fragment
   **561 B deployed vs 559 B** in main) and a layout self-integrity hash
   (`f80cb496…` deployed vs `44c63234…` local — hash256 of the locator blob, not
   a vk table).
2. The deployed genesis redeem differs in ~1.9 KB (its MSM section is a
   different build), the terminal redeem differs by +1 byte and op reshuffles.
3. The proof-INDEPENDENT MSM witness bytes (`wa` = the GLV joint decomposition)
   **match** the live actions byte-for-byte — the decomposition algorithm is
   stable across generations.
4. The proof-dependent MSM state pushes and `zInv` do NOT match my port's output
   for the live (n0, n1) — and the live genesis witness push-0 does NOT contain
   `vk_x = IC0 + n0·IC1 + n1·IC2` for EITHER vkey we hold (committed or
   artifacts-era), although its fields 4/5 ARE valid G1 points (i.e. a vk_x of a
   key we do not have, or a different field layout).
5. Consequence: the live pools' proofs were generated and their steps built by a
   runner worktree revision whose `witness.mjs`/MSM build is NOT the public
   main. This matches the documented "layout drift" (HANDOFF §4.4: the emitted
   layout depends on the repo state at generation time).

**Correction issued:** the gate3 registry note previously claimed the pool uses
the SAME verifying key as the wallet-committed `verification_key.json`
("wallet-compatible pool"). The on-chain witness data contradicts this — the note
now says the pool is NOT wallet-prover-compatible until the runner's
build256 vkey + worktree are re-verified. Note-detection (blocker 2) is
unaffected: the scan validates against the on-chain proven (n0, n1), never the
vkey.

## Runner-gated next steps (when the runner is back)

1. `diff` the runner's `/home/ubuntu/zkb/groth16_cashscript` worktree against
   the public main (esp. `densless-recovered/witness.mjs`,
   `pairfold5-msm/vkx-msm-asm.mjs`, `densless-msm/build.mjs` +
   `vkx-stages.mjs`) — recover the EXACT deployed witness algorithm.
2. Port it into the wallet's `verifier.js` behind the same `program` parameter;
   the byte-comparison harness against the live witness pushes (vkx@fields 4/5,
   per-cut states, zInv — built and used this session) is the acceptance test:
   it must reproduce the LIVE bytes for the live (n0, n1) before the wallet
   regenerates steps for the deployed pools.
3. Verify the runner's `build256/verification_key.json` against the
   wallet-committed key (lineage check that this session could only do locally).
4. Then the §7.2 live cross-wallet demo can use the WALLET builder end-to-end
   (covenant unlocking + funding + carrier from the wallet; steps either from
   the wallet port once (2) passes, or from the runner's pipeline).

For NEW pool deployments (Path A), the wallet is already end-to-end: generate
the verifier program from the CURRENT bench main (the exact algorithm my port
reproduces byte-exactly), export the program constants like `verifier-program.js`,
and the wallet builds every part of the action tx itself.
