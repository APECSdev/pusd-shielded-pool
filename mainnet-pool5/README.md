# mainnet-pool5 — the 2026-11-27 three-links pool (SHIELD · TRANSFER · UNSHIELD, all REAL PUSD)

The old-gen (Gate-5-form) mainnet pool deployed and driven end-to-end on 2026-11-27 to
produce the three REAL-PUSD lifecycle links for the bitcoincashresearch announcement
(topic 2666). All three are CONFIRMED on mainnet:

| link | txid |
|---|---|
| SHIELD (the user's 4 units; pv=4) | `627013caa09b2e42ae4229bbd15bc2f53561911d1ccb0e09d260af937c012403` |
| TRANSFER (the 100-PUSD confirmed op from 11-20) | `4fda8a8b63ff2ef82cc1f5a9ad89bdcbbc86fec254e9c08bb1b874312f6b544f` |
| UNSHIELD (2 PUSD paid out publicly; pv=2) | `998a04748b6db7845cd06ef37ab0a51c26b685c0a458a59f7700df873215734d` |

Deploy chain (category = PREP1 txid `0631da2b…`): PREP1 `0631da2b…` → PREP2 `82684496…`
(fee-fix recovery) → GENESIS `21a3240c…` → DEPLOY `d122abab…` (state NFT + the 8-input
steps + holdings 1 FT + the combined PUSD/BCH change).

## The two blockers that forced this pool (both measured, both recorded)

1. The 11-20 pool (`dd1e3506…`, artifact pool3b) carries VESTIGIAL v1 balance arithmetic
   in its state path (`newBalance = 0 + pv − 2·sign·pv` on the state NFT's tokenAmount,
   which is structurally 0) — every pv≠0 op is impossible. Its 100-PUSD holdings are
   permanently locked. `pool5.cash` = the same covenant minus those four lines
   (fork-compiled, `optimizeFor=opcost`; −30 B, one UTXOTOKAMT removed, tails identical).
2. The 11-13 bench terminal pins `OP_TXINPUTCOUNT OP_7 OP_EQUALVERIFY`
   (densless-recovered/terminal.mjs:335) — no funding input possible. `mainnet-pool5`
   edited the pin to `OP_8` (one byte, same length — redeem-length convergence and the
   worker-locking root unchanged); all five steps VM-verified at 8 inputs.

## The honest seed

Notes `{1, 0}` == holdings 1 FT: the deploy took 1 of the user's 5 units as the holdings
seed; the SHIELD brought the remaining 4 (pv=4). After the UNSHIELD (pv=2): notes {2,1},
holdings 3 FT, payout 2 PUSD + 1,000 sats back to the wallet.

## Files

- `pool5.cash` / `pool5.artifact.json` — the fixed covenant (source + fork artifact).
- `gen-pool5-vectors.mjs` — the seed vector + both proofs under the UNCHANGED Nov-13
  solo zkey, with the **layout gate**: the covenant reads n1/n0 at fixed offsets
  1792/1825, valid only when the genesis unlocking is exactly 7,904 B — `genesis[1] =
  bigIntToVmNumber(w.selector)` and a selector of 0 encodes to ZERO bytes (a one-byte
  shift; Groth16 proofs are prover-randomized, so the layout re-rolls per proof and the
  script re-rolls until it matches).
- `matrix5-deploy.mjs` — genesis → deploy (resume-capable: RESUME_ANCHOR/RESUME_BCH
  after a partial run; the genesis fee MUST be ≥ 459 sats — a 300-sat attempt died
  `min relay fee not met (code 66)`).
- `op5-shield.mjs` / `op5-unshield.mjs` — the two actions (8 inputs: steps×5 + state +
  holdings + the funding/deposit input). Every input VM-evaluated in BOTH modes before
  broadcast; `BROADCAST=1` gates every broadcast.
- `unshield-probe.mjs` / `statecheck.mjs` — the isolation probes that found the two
  blockers above (the state-path balance require + the terminal count pin) and verified
  the current notes ARE the recorded demo secrets (§10 of the V4H handoff was a byte-order
  artifact — nothing was missing).

DEMO ONLY: this pool runs the old 2-in/2-out circuit (no nullifier set — R2 class) and
the F6-withdrawn densless verifier under the 1-of-1 solo ceremony; it must never hold
real value beyond demo scale. The PERMANENT pool is the v4h C architecture — see
`wip-role2-hook/V4H-DEPOSIT-LIVE-2026-11-27.md` (its deposit went LIVE the same day).
