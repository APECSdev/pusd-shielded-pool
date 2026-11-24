# SOUND-VERIFIER-BUILD.md — the reviewed sound verifier, built under OUR verifying key

**Status: BUILD GATE PASSED (2026-11-24).** The reviewed `bch-groth16-bn254-sound-native`
program has been regenerated from source under **this pool's** verifying key and passed every
internal assertion of its own build, including acceptance of our real proof on the BCH-2026 VM
in both consensus and standard mode. Nothing has been deployed.

---

## 1. Why this matters

The verifier every pool here runs — `densless-msm` — was **withdrawn by its author on
2026-10-26 under finding F6** (`chunked/bn254/densless-msm/README.md`: the shared Miller event
consumes slopes without the tangent/chord equations, and the terminal's predicate compares a
value with itself instead of checking the B endpoint). Its replacement,
`bch-groth16-bn254-sound-native`, is independently reviewed (2026-10-26), smaller and cheaper
than what we shipped. This document records getting that replacement to build under **our** VK,
which is the first hard gate before it can hold value.

## 2. The injection point (this is the good news)

The sound verifier's build is **already VK-parametric**. `chunked/bn254/sound-si-gls/math.mjs:20`:

```js
// BN_VK_FIXTURES (optional, Track 11 real keys): a fixtures file of the same shape
// ({vk, fixtures}) for another BN254 VK with exactly 2 public inputs. Unset = the densless VK.
export const FIXTURES = JSON.parse(readFileSync(process.env.BN_VK_FIXTURES
    ? process.env.BN_VK_FIXTURES
    : new URL('../densless-recovered/public-fixtures.json', import.meta.url)));
assert.equal(FIXTURES.vk.ic.length, 3, 'the verifier binds exactly 2 public inputs (IC0..IC2)');
```

So the work is *not* "write a constant generator for a new VK". It is: produce a
`{vk, fixtures}` file in the bench's shape and point `BN_VK_FIXTURES` at it. Everything else —
the 33-state chain, the schedules, the delta slices, the affine kernels — is derived at load
time and re-asserted against `@noble/curves`.

## 3. The fixture pipeline (and the stale file it replaces)

`build/eval-proofs.json` **cannot** be used as a fixtures source. Measured:

| source | result |
|---|---|
| `build/eval-proofs.json` vs `build/verification_key.json` | **0/3** satisfy the Groth16 equation, in all four G2 coordinate conventions |
| freshly generated proofs vs the same VK | **5/5** satisfy it, with `proof` and `vk` both in the `c0c1` G2 convention |

The VK itself is **not** stale: `snarkjs zkey export verificationkey build/pool_final.zkey`
reproduces `build/verification_key.json` byte-for-byte. The proofs in `eval-proofs.json` are
what is wrong — the file was written to drive the *covenant* test (scenario-chosen roots), not
to be a verifiable proof set. **Do not treat it as one.**

Regeneration (on the apecsdev VM, `~/zkb/pusd-shielded-pool`):

```sh
# gen-our-proofs.mjs is gen-eval-proofs.mjs with three changes:
#   1. wasm  build/pool_js/pool.wasm      -> build256-vm/pool_js/pool.wasm
#   2. out   build/eval-proofs.json       -> /home/apecs/cov/our-proofs.json
#   3. the witness input names: the canonical circuit has NO `assetCategory` signal.
#      It takes `assetCategoryHi` / `assetCategoryLo` (two 128-bit limbs). The stale
#      generator passes `assetCategory` and fails with "Signal assetCategory not found".
node gen-our-proofs.mjs      # 5 scenarios, ~17 s each
```

Category limb split for `2469acc5…2544` (verified: `hi·2^128 + lo == int(category,16)`):

| limb | value |
|---|---|
| `assetCategoryHi` | `48400903255161948369394347083175674787` |
| `assetCategoryLo` | `340064865781103239580466282381422110020` |

Then convert snarkjs → the bench's `{vk, fixtures}` shape (G1 `[x,y,1]` → `{x,y}`;
G2 `[[x0,x1],[y0,y1]]` → `{x:{c0,c1}, y:{c0,c1}}`; `publicSignals` → `publicInputs`), and build:

```sh
cd ~/zkb/groth16_cashscript/chunked/bn254/bn-native-sound
BN_VK_FIXTURES=/home/apecs/cov/our.fixtures.json node build.mjs
```

`build.mjs` requires **fixtures 0 and 4** (it cross-checks two of them), so the fixture set
needs at least five entries.

## 4. Result — our program, our VK

```
code 7309 B sha256 5fd6a4bee213d2f8cd4e251afcfe894d15247421c860538debf0e93d95d9c5df; R 65 B; locking sha256 fe9cacfda1a0e0b2d9be7a0fe36831efd83733af6d8e20039020cb0c4d85db49
code pieces 3767 + 3542; role code 804 / 720 / 2372; prologue 7304
fixture 0: n_q 111, fills 94/31/118, unlocking 9314 / 9251 / 8748 = 27313, score 27567
  input 0: op 6998295 cons / 7032471 std of 7484000 (margin 6.49% / 6.03%)
  input 1: op 6951402 cons / 6985578 std of 7433600 (margin 6.49% / 6.03%)
  input 2: op 6574203 cons / 6606971 std of 7031200 (margin 6.5% / 6.03%)
```

| field | value |
|---|---|
| code | **7,309 B** · sha256 `5fd6a4bee213d2f8…c5df` |
| redeem `R` | **65 B** · sha256 `31b38b05822dc267…9a5b` |
| **program locking (P2SH32)** | **`aa205233f888295170f09abaff3ffca7f8eb659034ed413c5856e214bcde5be09f6f87`** |
| `vkDigest` | `38876f95ad30fe82…a783` |
| role function ids | `22 / 23 / 24` |
| fixture 0 score | **27,567** (the reference build under the densless VK scores 27,624) |
| fixture 0 unlockings | 9,314 / 9,251 / 8,748 = **27,313 B** total |
| op margins | **6.03% standard / 6.49% consensus** on all three inputs |

### What `build.mjs` asserted (any failure aborts, so all of these passed)

- every baked constant recomputed and asserted against `@noble/curves` at load;
- per-role schedules (digits, boundary flags), delta slices and start states asserted against
  the single-input schedule and the single delta chain;
- the program built twice, byte-identical;
- fixtures 0 and 4: the 33 states equal the reviewed single-input SI-GLS prover's states, and
  the role-split run chained by the handovers equals one uninterrupted run over all 65 events;
- the code is exactly what `R` hashes; function ids distinct;
- **fixture 0 accepted in consensus and standard mode** with prover-sized fillers, and a
  **tampered state rejected**.

That last line is the acceptance gate: our real proof, our VK, the BCH-2026 VM, both modes.

## 4b. Red team under our VK — 151 runs, 0 accepted

```sh
node export-our.mjs /home/apecs/cov/our-vectors.json        # steps from fixture 0 under our VK
node redteam.mjs our-vectors.json our-redteam.json our-redteam-report.json
# runs 151 (143 in the bench file), accepted 0
# positive controls accepted: fixture 0 (vectors); fixture 0, lattice-shifted GLS decomposition
```

Every rejection class the artifact ships, re-run against **our** program and **our** proofs:

| kind | runs | | kind | runs |
|---|---|---|---|---|
| handover | 20 | | tamper-quotient | 9 |
| layout | 16 | | gls-digit | 7 |
| inverse-norm | 15 | | non-canonical-state | 3 |
| invalid-proof-point | 14 | | tamper-transcript | 3 |
| **graph** | **10** | | non-canonical-quotient | 3 |
| staple | 10 | | quotient-cap | 3 |
| public-input-binding | 7 | | tamper-residue | 2 |
| tamper-state | 7 | | code | 2 |
| filler | 7 | | constants | 2 |
| non-canonical-coordinate | 6 | | g2-subgroup | 1 |
| public-input-encoding | 4 | | | |

### The graph tests answer the covenant-sibling question empirically

All ten shape tests reject — including the three that matter for us:

```
input 2 replaced by a foreign P2SH32(OP_TRUE) input        => reject
foreign P2SH32 input at index 0 carrying the honest pushes => reject
foreign P2SH32 input at index 1 carrying the honest pushes => reject
foreign P2SH32 input at index 2 carrying the honest pushes => reject
```

So the sound verifier does not merely *document* that it forbids a foreign-locking sibling — it
enforces it, and it rejects a foreign script **even when that script carries the honest pushes**.
This confirms from the verifier's side what `pin-sibling-test.mjs` showed from the covenant's
side: the two cannot be composed as siblings. Extending role 2 is the route.

### Fixture-degeneracy trap (found, fixed, worth recording)

The **first** red-team run under our VK reported `accepted 1`:

```
ACCEPTED: claim n0 := fixture 1 n0 (honest witness otherwise; DG recommitted)
```

That was **not** a soundness failure. Our first five scenarios reused the same input notes, so
fixtures 0 and 1 shared one `n0` (the merkle root) — the "tamper n0" run was therefore a no-op
on an already-honest witness, and accepting it was correct behaviour. The fixture set was
degenerate for the public-input-binding test, not the verifier.

Fix: every scenario now uses distinct input notes (`rho`/`r` offset per scenario), giving
**5 distinct `n0` values of 5**. Re-run: `accepted 0`.

**Recorded because the failure mode is dangerous in both directions:** a degenerate fixture set
makes a public-input-binding test vacuous, so a green run proves nothing. The check is
`distinct n0 values == fixtures` — verify it before trusting a red-team pass.

## 5. What this does NOT do

- **Not deployed.** No pool uses this program yet.
- **Does not compose with the covenant as it stands.** The sound verifier's graph pins
  `TXINPUTCOUNT == 3` and `UTXOBYTECODE(j) == UTXOBYTECODE(OP_INPUTINDEX)` for every j, and its
  spec says "No funding or fee input with another locking can be added". Our pool needs a
  covenant sibling and a fee input, so the route is to extend its **third role** with the pool
  rules — the integration the artifact documents ("applications that release funds add output
  rules in role 2").
- **Swept under our VK since 2026-11-24 (later session) — but only over REAL proofs.** The stock
  `sweep.mjs` mints proofs for chosen public inputs through the densless-fixtures trapdoor, which
  does not exist for our ceremony VK. The snarkjs minter (`gen-sweep-proofs.mjs`) + `sweep-ours.mjs`
  ran the sweep over 70 cases (5 fixtures + lattice-shifted witness + 64 random real proofs):
  **0 failed** — every case accepted in consensus AND standard at prover-sized fills and at the
  10,000 B cap, cap rule `op ≤ 7,550,832` everywhere. Min margins 6.00% std / 6.45% cons; max
  at-cap op 7,076,392 std (input 0, cap margin 11.91%); nq range 99-123. The trapdoor-forced
  extremes (every-nibble-15 etc.) remain unreachable under our VK — those are measured only under
  the reference VK (stock `sweep.json`), and their transfer to our build is an argument (identical
  code layout, fixed-size constants ⇒ VK-independent op cost), not a measurement.
- **`worstCaseProof` is now measured for our key** (smallest input-0 standard margin, the bench
  definition): **`sweep-ours-v1a shield #13`**, exported into `our-vectors.json` by the updated
  `export-our.mjs` (steps + 4 extraValidProofs + worstCaseProof — the bench shape, complete).
  It is the worst case reachable by REAL proofs, not the forced extreme the trapdoor would allow.
- **The covenant sibling pin (commit `61777c6`) is still undeployed.** Every live pool carries
  the unpinned covenant, which accepts a one-byte `OP_1` at the genesis index
  (`pin-sibling-test.mjs`, 6/6).

## 6. Next gates, in order

1. **Extend role 2 with the pool rules** — DONE 2026-11-24 (implemented WIP, gate 1 passed):
   `wip-role2-hook/pool-hook.mjs` implements the 12 checks (state category + stored root,
   carrier size/prefix/limbs, `n1 == actionHash` with all eight preimage fields reversed to
   big-endian, the raw-LE nullifier fold, balance arithmetic, the new `TXOUTPUTCOUNT == 2 + sign`
   pin, out1 locking/category/commitment/amount, the conditional unshield payout, and a dynamic
   drop-to-entry tail). `wip-role2-hook/pool-test.mjs` passes **14/14 under our VK** — 3
   acceptance controls (transfer pv=0, shield pv=250, unshield pv=400) + 11 rejection classes,
   with the full program (graph + hook + final pairing) executing end-to-end. All findings and the
   probe set: `wip-role2-hook/STATUS.md`.
2. Redeploy-path items — 1-3 DONE 2026-11-24, in order:
   ✅ **Fill sizing against pool-shaped transactions** (`wip-role2-hook/pool-tx.mjs`): the
   stock sizer/`programOf` build TOKENLESS source outputs (setOutputs alone cannot fix it),
   so the hook died at check 2 during sizing and fills stayed [0,0,0]. The pool-shaped loop
   sizes correctly: acceptance controls now run at **exactly 94.0% of budget** — fixture 0
   fills [0,0,171] (6,647,159 op of 7,073,600), fixture 1 [0,0,235], fixture 2 [0,0,66].
   Inputs 0/1 legitimately have empty fillers in the hooked build (the code pieces are
   longer, so their budgets already cover the graph).
   ✅ **Hook priced** (`wip-role2-hook/pool-cost.mjs`, statement→slices difference method):
   **33,156 op standard / 32,260 op consensus, 427 B** — under half the ~85k estimate.
   ✅ **Extended red team under the hooked program** (`wip-role2-hook/pool-redteam.mjs`):
   the stock 151-scenario list evaluated against the honest pool shape — **146 runs,
   0 accepted** (5 filler-tamper scenarios inexpressible: inputs 0/1 have empty fillers),
   both positive controls accepted. The layering confirmed: public-input claims die at the
   hook (`r2:p4`), proof tampering dies in the graph (`G1C@17`, `r2:t:endpoint`).
   ✅ **snarkjs-based minter + liveness sweep under our VK** (2026-11-24, later session):
   `gen-sweep-proofs.mjs` (repo root) mints seeded random REAL proofs against our zkey
   (~35-50 s each); `sweep-ours.mjs` (plain, 70 cases) and `pool-sweep.mjs` (HOOKED program,
   pool-shaped funded scenarios, 69 cases) both ran **0 failed**, cap rule everywhere; the
   hooked program binds at input 2 with 6.00% std margin, exactly the design target
   (`wip-role2-hook/sweep-ours-report.json`, `pool-sweep-report.json`, `REVIEW.md`).
   ⬜ Independent review (new bytes = new review — package prepared: `wip-role2-hook/REVIEW.md`).
   ⬜ One combined redeploy — BLOCKED on the review.
3. Get the extended program reviewed — it is new bytes, which is exactly how F6 and the v2 layout
   bug happened.
4. Redeploy the pool with the pinned covenant **and** the extended verifier, in one deploy.
