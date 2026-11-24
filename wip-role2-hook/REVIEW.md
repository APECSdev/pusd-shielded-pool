# wip-role2-hook/REVIEW.md — the independent-review package (open item 4)

**Status: documentation + reproduction package. Not a gate. Not deployed.**

USER CORRECTION (2026-11-24 PM): there is no independent-review option at this time and the
user never ordered one — the "independent review" open item originated in a previous
session's handoff notes ("new bytes are new review"), not from the user, and has been
REMOVED as a precondition for deployment. The user's recorded quality bar is: **Nito Cash's
own client is the FINAL approval for any deployed result.** This file remains what it is good
at being: a complete record of the scope, the bytes, the claims, the reproduce commands and
the honest limitations, for any future reader (including the Nito Cash team).

## 1. Scope — what is under review

The reviewed base is upstream `mr-zwets/groth16_cashscript` at commit `4571af9`
("batch cost model: relative imports instead of a worktree path"), directory
`chunked/bn254/bn-native-sound/` — the independently reviewed (2026-10-26)
`bch-groth16-bn254-sound-native` verifier. On the build VM
(`~/zkb/groth16_cashscript/chunked/bn254/bn-native-sound/`), `git status` shows:

- **All role-2 work is NEW FILES** (untracked): `pool-hook.mjs`, `pool-build.mjs`,
  `pool-test.mjs`, `pool-tx.mjs`, `pool-cost.mjs`, `pool-redteam.mjs` +
  `pool-redteam-report.json`, `sweep-ours.mjs`, `pool-sweep.mjs`, `export-our.mjs`, the
  `probe-*.mjs`/`trace-*.mjs`/`hook-*.mjs` investigation instruments.
- **No stock SOURCE file in `bn-native-sound/` is modified.** The only modified file there is
  `build.json`, a GENERATED artifact (rewritten by `build.mjs` when the program was rebuilt
  under our VK via `BN_VK_FIXTURES`; `sweep-ours.mjs` asserts the built code against it).
- Two PRE-EXISTING, UNRELATED tree diffs (both predate the hook work, neither is in scope):
  `chunked/bn254/densless-recovered/terminal.mjs` (the nito.cash v4-era `OP_5 → OP_7`
  input-count pin, inside the WITHDRAWN densless verifier — nothing to do with the sound
  verifier or the hook) and the repo-root `package.json` (the documented npm-parseable
  minimal manifest; stock original kept at `package.json.orig`).

The pusd-shielded-pool commits carrying this work (all pushed to `origin/master`):
`22afadb` (build gate) · `eeac3bb` (red team under our VK, 151/0) · `5cdba1f` (design) ·
`3dcb091` (implementation) · `243a416` (14/14) · `1907226` (sizing + pricing + extended red
team) — plus this session's additions: `gen-sweep-proofs.mjs` (the snarkjs liveness minter),
`gen-our-proofs.mjs` (the fixture generator, previously VM-only, now committed — the v4
lesson: reproducible generator source is a review requirement), `sweep-ours.mjs`,
`pool-sweep.mjs` and this file.

## 2. The bytes under review

| object | plain build (no hook) | hooked build (role-2 hook) |
|---|---|---|
| program code | 7,309 B · sha256 `5fd6a4bee213d2f8cd4e251afcfe894d15247421c860538debf0e93d95d9c5df` | 7,737 B (plain + 428 B; the priced role-2 slice is 427 B, `pool-cost.mjs`) · sha256 `89a8ac1426e818a36ceae4308fcb65f15d578e1cbf0143f0dfc76f3e4889a3f3` |
| redeem R | 65 B · sha256 `31b38b05…9a5b` | 65 B · sha256 `14ab8983cc2b74366731580dfeeabfcce681b38f508b98ce21af1e5078d5178b` (same length — the hook rides in the code PIECES, not the redeem; only the baked code-digest constants differ) |
| code pieces | 3,767 / 3,542 | 3,981 / 3,756 (+214 / +214 = the hook bytes) |
| P2SH32 locking | `aa205233f888295170f09abaff3ffca7f8eb659034ed413c5856e214bcde5be09f6f87` | `aa208caa897c21a9cd65fd617efec64d06c91f766d72334d3e2c51b96b280ea7b10487` |
| role-2 hook cost | — | 427 B · 33,156 op standard / 32,260 op consensus |

The verifying key is ours (the 2026-11-13 solo-ceremony zkey, `build/pool_final.zkey`
97,716,000 B on the VM; VK exported byte-identical by snarkjs), wired through
`BN_VK_FIXTURES=/home/apecs/cov/our.fixtures.json` (vk `ic.length = 3`, 2 public inputs).
`vkDigest 38876f95ad30fe82…a783`, role function ids 22/23/24. The hook is registered through
the STOCK integration point (`script.mjs` `setCovenant`, the same one the upstream SP1
worked example `real-keys/covenant.mjs` uses) — we did not fork the verifier.

## 3. What the hook enforces (the review target proper)

`pool-hook.mjs` implements the deployed covenant's rules INSIDE role 2, right after STMT
decode, with n0/n1 on the stack. Twelve checks (p1..p11 + 8b):

1. `tx.version == 2`
2. active input (index 2) carries the pool category as a MUTABLE NFT
3. out0 = the exact 169-byte OP_RETURN carrier `nf0|nf1|cm0|cm1|newRoot|pv(8)|sign(1)`
4. carrier split; pv, sign BIN2NUM'd; sign ∈ {0,1}
5. n0 == the state NFT's stored merkle root (bytewise — NUMEQUAL on 32-byte pushes is a sign trap)
6. n1 == SHA256(BE preimage of the eight carrier limbs) with the top 3 bits cleared — the
   asset-pool.cash actionHash, byte orders included (every limb REVERSEBYTES'd; the nullifier
   fold uses the RAW LE forms, line 148)
7. newNull == SHA256(oldNull | nf0 | nf1)
8. newBalance == balance + pv − 2·sign·pv ≥ 0
8b. TXOUTPUTCOUNT == 2 + sign (pins the shape; makes the payout rules total)
9. out1: own P2SH32(R), pool category mutable NFT, commitment == newRoot|newNull, amount == newBalance
10. sign==1 ⇒ out2 pays pv in the bare category
11. dynamic drop-to-entry-depth tail (name lists leak pick() copies)

Design doc: `ROLE2-POOL-HOOK-DESIGN.md` (status: implemented WIP). The critical design claim
to scrutinize: **the carrier (out0) is a convenience, NOT a trust anchor** — the prover cannot
alter it without breaking n1's binding to the proof, and that binding is the GT-GLS fold role
2 already enforces. If a reviewer breaks that argument, everything above falls.

## 4. The claims and their evidence

| # | claim | evidence | reproduce (VM, from `chunked/bn254/bn-native-sound/`) |
|---|---|---|---|
| C1 | acceptance: 3 controls (transfer pv=0, shield pv=250, unshield pv=400) + 11 rejection classes, 14/14 | `pool-test.mjs` | `BN_VK_FIXTURES=/home/apecs/cov/our.fixtures.json ~/bin/node pool-test.mjs` |
| C2 | extended red team: the stock 151-scenario list against the honest pool shape — 146 runs, 0 accepted (5 inexpressible: inputs 0/1 have legitimately empty fillers), both positive controls accepted | `pool-redteam.mjs` + committed `pool-redteam-report.json` | `BN_VK_FIXTURES=… ~/bin/node pool-redteam.mjs` |
| C3 | layering: public-input tamper dies at the hook (`r2:p4`) BEFORE the graph's binding check; proof-point tampering dies in the graph (`G1C@17`); B-outside-G2 at `r2:t:endpoint` | guard fields in the report | read `pool-redteam-report.json` (`at` / `rejectingInputs`) |
| C4 | sizing: controls at exactly 94.0% of budget, fills [0,0,171]/[0,0,235]/[0,0,66]; hook priced 33,156 op std / 32,260 op cons, 427 B | `pool-tx.mjs`, `pool-cost.mjs` | run `pool-cost.mjs` |
| C5 | liveness under our VK with REAL proofs: plain program **70 cases, 0 failed** (min margins 6.00% std / 6.45% cons, max at-cap op 7,076,392 = cap margin 11.91%, nq 99-123); hooked program **69 cases, 0 failed** (input 2 binds at 6.00% std — the design margin; max at-cap op 6,749,569, cap margin 15.97%); `worstCaseProof` = `sweep-ours-v1a shield #13`, exported to `our-vectors.json` | `sweep-ours.mjs` + `sweep-ours-report.json`, `pool-sweep.mjs` + `pool-sweep-report.json`, `our-sweep-proofs-a/b.json`, `gen-sweep-proofs.mjs` (all committed) | see §5 |
| C6 | harness landmines a reviewer must know when reading the tests: Node `Buffer` aliasing vs libauth's in-place `slice()` mutations (pass ONLY plain `Uint8Array`s); `OP_SIZE` is NON-POPPING on the BCH-2026 VM; REVERSEBYTES byte-order conventions | `STATUS.md` findings 1–3, `probe-proxy.mjs` etc. | read `STATUS.md`; run `probe-proxy.mjs` |

## 5. Reviewer procedure (apecsdev VM, `~/zkb/…`)

```sh
export BN_VK_FIXTURES=/home/apecs/cov/our.fixtures.json
cd ~/zkb/groth16_cashscript/chunked/bn254/bn-native-sound

~/bin/node pool-test.mjs          # expect: 14/14 match expectation
~/bin/node pool-redteam.mjs       # expect: 146 runs (of 151), accepted 0, controls accepted
~/bin/node sweep-ours.mjs  /tmp/r1.json /home/apecs/cov/our-sweep-a.json [/home/apecs/cov/our-sweep-b.json]
~/bin/node pool-sweep.mjs  /tmp/r2.json /home/apecs/cov/our-sweep-a.json [/home/apecs/cov/our-sweep-b.json]
```

Program-bytes reproduction (prints code/R/pieces/locking for both builds):

```sh
BN_VK_FIXTURES=$BN_VK_FIXTURES ~/bin/node -e '
import("./script.mjs").then(async (s) => {
  const {covenantHook, covenantParams} = await import("./pool-hook.mjs");
  const {p2sh32} = await import("./vm.mjs");
  const {createHash} = await import("node:crypto");
  const sha = (b) => createHash("sha256").update(b).digest("hex");
  const CAT = Buffer.from("2469acc5afa4b10cb5b5c04afb89c3a3ffd61c5da9c01e26d00951cae2a02544","hex");
  const plain = s.buildProgram();
  s.setCovenant(covenantHook(covenantParams({categoryOnChain: Buffer.from(CAT).reverse().toString("hex")})));
  const hooked = s.buildProgram();
  for (const [n, p] of [["plain", plain], ["hooked", hooked]])
    console.log(n, "code", p.code.length, sha(p.code), "| R", p.R.length, p.R.toString("hex"),
      "| pieces", p.pieces.map((q) => q.length).join("/"), "| locking", Buffer.from(p2sh32(p.R)).toString("hex"));
});'
```

Mint new sweep proofs (only needed to extend the sample; ~35 s/proof, VM-exclusive):

```sh
cd ~/zkb/pusd-shielded-pool && ~/bin/node gen-sweep-proofs.mjs <count> <seed> /home/apecs/cov/<out>.json
```

## 6. Honest limitations

- **worstCaseProof's forced-extreme classes are unreachable under our VK.** The stock sweep
  mints proofs for chosen public inputs via the toxic-waste trapdoor; our ceremony zkey has no
  trapdoor, and real circuit witnesses cannot hit measure-zero statement shapes (every-nibble-15
  etc.). Those extremes were measured by the stock sweep under the reference VK, and op cost
  for a given (statement, witness, fill) is VK-independent (identical code layout and
  fixed-size baked constants) — but this transfer is an argument, not a measurement, and a
  reviewer should decide how much weight it deserves. What our sweeps measure is the worst case
  reachable by proofs that can actually be produced for this pool.
- The 5 fixtures and the minter share one category (`2469acc5…`, the committed hook ctor
  param) — the hook cost is category-independent (fixed 32-byte compare), but a reviewer can
  re-derive with a different category if desired.
- Review of the hook does NOT re-review the underlying verifier (that was the 2026-10-26
  independent review) — but confirm that claim yourself; that is the point of this package.
- Nothing is deployed. Every live pool still carries the withdrawn F6 verifier AND the
  unpinned covenant; the combined redeploy (open item 5) is blocked on THIS review.

## 7. After the review

Record the reviewer, date, verdict and any findings in `STATUS.md`, then proceed to the one
combined redeploy (pinned-covenant logic inside the verifier, single deploy) — open item 5.
