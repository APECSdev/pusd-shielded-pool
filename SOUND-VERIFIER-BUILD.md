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

## 5. What this does NOT do

- **Not deployed.** No pool uses this program yet.
- **Does not compose with the covenant as it stands.** The sound verifier's graph pins
  `TXINPUTCOUNT == 3` and `UTXOBYTECODE(j) == UTXOBYTECODE(OP_INPUTINDEX)` for every j, and its
  spec says "No funding or fee input with another locking can be added". Our pool needs a
  covenant sibling and a fee input, so the route is to extend its **third role** with the pool
  rules — the integration the artifact documents ("applications that release funds add output
  rules in role 2").
- **Not re-swept or re-red-teamed under our VK.** `sweep.mjs` / `export.mjs` mint new proofs
  through the densless-fixtures trapdoor, which does not exist for our VK; those runs need a
  snarkjs-based minter. `redteam.mjs` operates on a vectors file and can be pointed at vectors
  built from our five proofs.
- **The covenant sibling pin (commit `61777c6`) is still undeployed.** Every live pool carries
  the unpinned covenant, which accepts a one-byte `OP_1` at the genesis index
  (`pin-sibling-test.mjs`, 6/6).

## 6. Next gates, in order

1. Build a vectors file from our five proofs and run `redteam.mjs` — the rejection battery under
   our VK, recorded as **our** run.
2. Extend role 2 with the pool rules (state NFT continuity, new commitment, balance arithmetic,
   unshield payout at a fixed output index, `actionHash == n1`). Role 2 has
   `(41 + 9792) × 800 ≈ 7.87M` with ~6.66M used → ~1.2M spare; the covenant logic is ~85k op.
3. Re-run the sweep (liveness) and the red team after the extension, then get it reviewed.
4. Redeploy the pool with the pinned covenant **and** the extended verifier, in one deploy.
