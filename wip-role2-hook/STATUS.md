# wip-role2-hook — status

**The role-2 pool hook WORKS: pool-test passes 14/14 under our own VK** — 3 acceptance
controls (transfer pv=0, shield pv=250, unshield pv=400 — the unshield exercises the
conditional payout branch) and 11 rejection classes, with the COMPLETE program (prologue,
STMT decode, graph solo, all 12 hook checks, then the post-hook GT-GLS fold and the final
pairing verify) executing end-to-end. Not deployed — the deployment is the remaining task (open item 5);
the "independent review" gate was removed by user directive 2026-11-24 PM (never a user-ordered process;
no reviewer exists at this time — the user's quality bar is Nito Cash's own client as final approval).

```
--- control: a real pool transition ---
ok   ACCEPT  fixture 0 (pv=0, sign=0)          ok   ACCEPT  fixture 1 (pv=250, sign=0)
ok   ACCEPT  fixture 2 (unshield, pv=400)
--- rejections: carrier tampering ---           (newRoot / pv / sign / nf0 changed — all REJECT)
--- rejections: state input tampering ---       (wrong category / wrong stored root — REJECT)
--- rejections: out1 tampering ---              (wrong category / forged commitment / wrong amount — REJECT)
--- rejections: payout rules ---                (unshield missing payout / shield minting payout — REJECT)
14/14 match expectation
```

## The hook's checks (pool-hook.mjs, marks p1..p11)

1. tx.version == 2
2. active input carries the pool category as a MUTABLE NFT (state index = literal 2)
3. out0 = the 169-byte carrier: `OP_RETURN PUSHDATA1 <nf0|nf1|cm0|cm1|newRoot|pv(8)|sign(1)>`,
   exact size + prefix
4. carrier split into limbs; pv, sign BIN2NUM'd; sign ∈ {0,1}
5. n0 == the active input's stored merkle root (commitment[0..32), byte compare —
   NUMEQUAL on 32-byte strings is a sign trap)
6. n1 == SHA256(preimage) with the top 3 bits cleared, where the preimage is the eight
   32-byte BIG-ENDIAN fields `nf0|nf1|cm0|cm1|be32(pv)|be32(sign)|category|newRoot`
   — every carrier limb is REVERSEBYTES'd first (deployed covenant, asset-pool.cash
   lines 192-200: `nf0.reverse() … newMerkleRoot.reverse()`)
7. newNull == SHA256(oldNull | nf0 | nf1) — folded over the RAW LE forms (line 148: no reversal)
8. newBalance == balance + pv − 2·sign·pv ≥ 0 (UTXOTOKAMT reads the state amount)
8b. TXOUTPUTCOUNT == 2 + sign (pins the shape; makes the payout rules total, and blocks
    extra outputs even though consensus token conservation already limits totals)
9. out1: own P2SH32(R) locking, pool category as mutable NFT, commitment == newRoot|newNull,
   amount == newBalance
10. if sign==1: out2 pays pv in the BARE category
11. drop everything the hook created (dynamic drop-to-entry-depth loop, NOT a name list —
    pick() copies share names, so a name list drops only the topmost duplicate and leaks)

## Durable findings (the debugging saga, in order of discovery)

### 1. THE BIG ONE — Node `Buffer` + libauth = in-place corruption of your scenario

libauth's opcodes are written for plain `Uint8Array` stack items and use `item.slice()`
before mutating (e.g. `opReverseBytes` = `item.slice().reverse()`, `pushTokenExtendedCategory`
= `category.slice().reverse() + capByte`). **`Uint8Array.prototype.slice()` copies — but
`Buffer.prototype.slice()` is overridden to return a VIEW sharing memory.** If any
transaction field is a Node `Buffer`, every "pure" slice becomes an alias and the
"reversals" write straight through into your original objects:

- the carrier's five 32-byte limb fields get byte-reversed in place,
- `token.category` buffers flip per call (probe-mutate shows strict alternation),
- results become call-order-dependent, which is why this bug masqueraded as
  "UTXOTOKCAT returns reversed but OUTTOKCAT returns display" and as in-process vs
  fresh-process disagreements that sent me chasing VM-internal state for hours.

**Fix: pass ONLY plain `Uint8Array`s into the VM** (`new Uint8Array(buf)` copies).
The stock harness does this (`Uint8Array.from` everywhere) which is why the stock code
never hit it. A real node cannot mutate your transaction; this is purely a JS harness
hazard — but it silently corrupts any harness built with Buffers. probe-proxy proves the
writes bypass a Proxy over the Buffer (they go through views created from its ArrayBuffer).

### 2. OP_SIZE on the BCH-2026 VM is NON-POPPING

`[push 0xaa, OP_SIZE]` leaves `[aa, 01]`. Model it exactly as the stock FILL local
function does (script.mjs:75): `op(OP.SIZE, 1, name, sizeOut)` — pop 1, push **2**
(the operand returns under the size). A pop-1/push-1 model leaves an operand copy on the
runtime stack and shifts every later pick by one — that single leak produced the
original "one-slot offset" blocker recorded in the previous STATUS.

### 3. The deployed covenant's byte-order conventions (asset-pool.cash)

- actionHash preimage: ALL EIGHT 32-byte fields reversed to big-endian (lines 192-200);
  the carrier carries the LE covenant-arg forms, so the hook REVERSEBYTES's each limb
- nullifier fold: `sha256(old ‖ nf0 ‖ nf1)` over the RAW LE args (line 148) — no reversal
- the category ctor arg is the ON-CHAIN (reversed) order, matching introspection
- introspection pushes `reverse(stored category) + capability byte` for BOTH input-side
  and output-side token categories (shared helper, bch-2023-tokens.js:202-236)
- bare (no-NFT) token outputs push just the reversed category, no capability byte

### 4. libauth trace/debug facts

- the debug trace's `ip` is a BYTE OFFSET in the currently executing function's code
  (OP_INVOKE starts a fresh ip space per invoked function) — NOT an instruction index
- the instruction stream for input 2: witness data pushes → R (the 65-byte redeem:
  INPUTBYTECODE-extracts the code pieces from inputs 0/1, SHA256==Kcode check,
  OP_DEFINE + OP_INVOKE of the body) → the body dispatches to role 2's function
- the assembler's model can be recorded per emitted op by monkey-patching
  `Asm.prototype.emit` (model-diff.mjs, pick-diff.mjs) — that plus the VM trace's
  stack snapshots is the decisive divergence-finding instrument

### 5. Opcode numbers that matter here (verified live)

stock IX (script.mjs:15): INPUTINDEX 0xc0, TXINPUTCOUNT 0xc3, UTXOBYTECODE 0xc7,
INPUTBYTECODE 0xca. Hook additions, each probe-verified: TXVERSION 0xc2,
TXOUTPUTCOUNT 0xc4, OUTBYTECODE 0xcd, UTXOTOKCAT 0xce, UTXOTOKCOMMIT 0xcf,
UTXOTOKAMT 0xd0, OUTTOKCAT 0xd1, OUTTOKCOMMIT 0xd2, OUTTOKAMT 0xd3,
REVERSEBYTES 0xbc. All introspection ops POP their index. OP_SIZE does not pop.

## Files

| file | what it is |
|---|---|
| `pool-hook.mjs` | the hook: 12 checks, carrier parsing, dynamic tail, p-marks for tracing |
| `pool-test.mjs` | the 14-case acceptance harness (pool-aware: tokens on source outputs, carrier out0, state out1, payout out2) with per-check tracer |
| `pool-build.mjs` | registers the hook via setCovenant then imports the stock build.mjs |
| `pool-tx.mjs` | pool-shaped fill sizing (the stock sizer's loop, evaluated against the pool shape) |
| `pool-cost.mjs` | hook pricing via the statement→slices difference method |
| `pool-redteam.mjs` + `pool-redteam-report.json` | the stock 151-scenario red team ported to the hooked program, evaluated against the honest pool shape — 146 runs, 0 accepted |
| `sweep-ours.mjs` + `sweep-ours-report.json` | the liveness sweep under our VK with REAL snarkjs proofs — 70 cases, 0 failed (plain program) |
| `pool-sweep.mjs` + `pool-sweep-report.json` | the same sweep against the HOOKED program with pool-shaped fills — 69 cases, 0 failed |
| `export-our.mjs` | bench-vectors export under our VK; since the sweep it also emits `worstCaseProof` |
| `REVIEW.md` | the independent-review package (open item 4): scope, bytes, claims, reproduce commands, limitations |
| `gen-sweep-proofs.mjs` + `gen-our-proofs.mjs` (repo ROOT) | the snarkjs minter (random valid witnesses, seeded, ~35-50 s/proof) and the original 5-fixture generator — both now committed (reproducible generator source is a review requirement) |
| `our-sweep-proofs-a/b.json` | the 64 minted proofs (seeds `sweep-ours-v1a`/`v1b`) the sweeps consumed — committed so the reports are re-runnable without re-minting |
| `trace-dump.mjs` | per-state stack dump near the failure; FXI env picks the fixture |
| `probe-size.mjs`, `probe-ix.mjs`, `probe-cat2/3.mjs`, `probe-ops.mjs` | opcode semantics probes (pop/push arity, byte orders) |
| `probe-mutate.mjs`, `probe-carrier.mjs`, `probe-when.mjs`, `probe-isolate.mjs`, `probe-proxy.mjs` | the Buffer-aliasing investigation — repro and isolation of finding #1 |
| `probe-fresh.mjs` | single-scenario fresh-process runner (fills + opCost printout) |
| `carrier-hunt.mjs`, `model-diff.mjs`, `pick-diff.mjs`, `map-code.mjs` | divergence-finding instruments (trace vs assembler model vs disassembly) |

Run on the apecsdev VM from `chunked/bn254/bn-native-sound/` with
`BN_VK_FIXTURES=/home/apecs/cov/our.fixtures.json`. The liveness sweeps (same env):
`node sweep-ours.mjs <out> <minted.json...>` and `node pool-sweep.mjs <out> <minted.json...>`;
mint with `node gen-sweep-proofs.mjs <count> <seed> <out>` from `~/zkb/pusd-shielded-pool`.

## Open items — 1-3 AND 6 OF 6 DONE (2026-11-24, same day + later session)

1. ✅ **Fill sizing against pool-shaped transactions — DONE** (`pool-tx.mjs`). The stock
   `sizeFills`/`programOf` build TOKENLESS source outputs (the module-global `setOutputs`
   only swaps transaction outputs, which is why setOutputs alone could not fix it), so the
   hook died at check 2 during sizing and fills stayed [0,0,0]. `pool-tx.mjs` replicates
   the stock fill-growth loop verbatim but evaluates input 2 against the honest pool shape
   (state NFT on source output 2, carrier/state/payout outputs). Results — the acceptance
   controls now run at **exactly 94.0% of budget** (the 6% margin): fixture 0 fills
   [0,0,171] (6,647,159 op of 7,073,600), fixture 1 [0,0,235] (6,623,738 of 7,048,000),
   fixture 2 [0,0,66] (6,712,105 of 7,142,400). Inputs 0/1 legitimately have EMPTY fillers
   in the hooked build (the hook's code pieces make their unlockings longer, so their
   budgets already cover the graph).
2. ✅ **Hook priced — DONE** (`pool-cost.mjs`, the statement→slices difference method from
   upstream `pinned/covenant-cost.mjs`): **33,156 op standard / 32,260 op consensus,
   427 B of role-2 code** — under half the design's ~85k estimate. Range totals: hooked
   96,765 / plain 63,609 (standard). Totals: hooked 6,647,159 (94.0%) vs plain 6,610,435
   (94.0%), both sized.
3. ✅ **Extended red team under the hooked program — DONE** (`pool-redteam.mjs` +
   `pool-redteam-report.json`): the stock 151-scenario list ported verbatim, evaluated
   against the honest pool shape. **146 runs, 0 accepted** (consensus AND standard), both
   positive controls accepted (the pool-sized honest witness + the lattice-shifted
   alternative GLS witness). 5 stock scenarios are inexpressible in the hooked build: the
   input-0/1 filler-tamper runs assume non-empty fillers, and those inputs legitimately
   have empty fillers here (flipping a byte of an empty push is a no-op that would accept).
   The layering works exactly as designed — public-input claims (n0±1 with DG recommitted)
   now die at the HOOK (`r2:p4`, the stored-root compare) BEFORE the graph's binding check;
   proof-point tampering dies in the graph (`r0:statement > G1C@17`); B-outside-G2 dies at
   `r2:t:endpoint`; staples die in the roles' loops; shape swaps die at the redeem.
4. ~~Independent review~~ — **REMOVED as a gate by user directive (2026-11-24 PM): there is no
   independent-review option at this time and the user never ordered one.** The item originated
   in the previous session's handoff notes ("new bytes are new review"), not from the user.
   The user's recorded quality bar is: **Nito Cash's own client is the FINAL approval for any
   deployed result.** `REVIEW.md` remains as a documentation/reproducibility package for any
   future reader — it gates nothing.
5. ✅ **DEPLOYED — the role-2 pool is LIVE on chipnet (2026-11-24, confirmed block 345,413).**
   Runner-free end-to-end per user directive: anchor `b6ee4196da1b0e3d548a03ea86a63d61445cd38d74300b2f7a8725eea05ceb72`
   (= the category) → mint `48d458b86bd59e33be59e4c8015820272c69df586920818005b86c04a6dbd538`
   (minting NFT + 100,000,000 FT) → deploy `f8f215c3826b763805c71f0ee281b406cfa2e0d944f541dfdc3ae56e473b3319`
   (state NFT born at :0, commitment = the PUBLIC bootstrap root 551108f6…510f ‖ zeros — verified
   byte-identical to the v2/v4 on-chain genesis commitments), funded from the APECS faucet hot
   wallet (423,000-sat UTXO). Program rebuilt for the real category: code 7,737 B sha256
   `0e827602…`, R 65 B, pieces 3,981/3,756, locking `aa20cd37fe80b308ae414c2d342dae482256548f7280918b4b1946057f1b631d4acd87`.
   NO covenant, NO step fleet — every pool UTXO locked to the same program P2SH32; actions are
   SIGNATURE-FREE 3-input spends (TXINPUTCOUNT==3, fees ride the locked UTXOs' sats).
   **Op 1 SHIELD 1,000,000 executed**: real witness under our ceremony zkey (22.8 s prove),
   tx `582cefee285f2e3f9528c0958158bcb8c0eef72ff516d17dfcfa7e8180bb79a2` (28,138 B, fee 32,000
   sats = 1.14 sat/B), the COMPLETE program (prologue, STMT, graph, all 12 hook checks, GT-GLS
   fold, final pairing) ACCEPTED in consensus AND standard on all 3 inputs (7.03M/7.01M/6.65M op
   standard), balance 0 → 1,000,000, FT conserved exactly, accepted by chipnet.bch.ninja.
   Tooling (committed): `pool-deploy-role2.mjs`, `pool-op-role2.mjs`, `pool-refill-role2.mjs`
   (bench dir) + `role2-op-witness.mjs`, `role2-seeds.mjs` (repo root). State file:
   `/home/apecs/cov/role2-pool-state.json`.

   **THE FULL LIFECYCLE IS CONFIRMED ON-CHAIN (2026-11-24):**
   - op 1 SHIELD 1,000,000 — tx `582cefee…`, **block 345,415** (balance 0 → 1,000,000)
   - refill `de98e0df…` (2×16,000-sat action inputs) — block 345,417
   - op 2 TRANSFER (notes 2,3 → fresh notes, pv=0) — tx `17f1322b…`, **block 345,423**
   - refill `fe9e1aad…` — block 345,426
   - op 3 UNSHIELD 250,000 (sign=1: 250,000 FT paid out publicly to the wallet, 750,000
     shielded onward as notes 450k+300k) — tx `24cd6b42…`, **block 345,427**
   Every action: real witness under our ceremony zkey, the COMPLETE program VM-ACCEPTED in
   consensus AND standard on all 3 inputs before broadcast, FT conserved exactly, accepted by
   chipnet.bch.ninja, merkle-confirmed. Final state: root `19318325…`, balance 750,000,
   notes at tree 6,7.
   Remaining (follow-up work, not blockers): the nito.cash CLIENT integration (their committed
   VK 27f6ea03… and 7-input shape differ — asset swap + 3-input builder; their client is the
   user's final approval per standing directive) and the /research/shielded-pool site record.

   ### SECURITY NOTE — standing fuel/deposit UTXOs are not author-bound (surfaced by the user
   2026-11-24 PM). The old pools bound every deposit and fee to its author with a SIGNATURE
   (the P2PKH funding input, input 6 in the 7-input shape). The role-2 pool has NO signature
   anywhere (TXINPUTCOUNT==3 is pinned) and the hook does not check inputs 0/1's token data,
   so: (a) standing FUEL UTXOs can pay any valid action's fee (theft-of-service); (b) more
   seriously, any note-holder who front-runs can consume a standing FT DEPOSIT as their own
   shield's input 0 with pv = the deposit (their witness is valid; consensus FT conservation
   is satisfied exactly; the deposit lands in THEIR notes). The exposure exists ONLY in the
   window between the lock confirming and the action confirming — nothing standing is at risk
   after the action (the current pool holds no standing deposits/fuel). Client rule until
   fixed: broadcast the lock and the action TOGETHER — the action may spend the lock's
   UNCONFIRMED outputs (standard relay accepts mempool chains; first-seen wins the state
   double-spend), closing the window to ~zero. The durable fix — ✅ IMPLEMENTED AND DEPLOYED
   2026-11-24 PM (the v2 record below): hook checks 4c+4g tag the lock outputs with an NFT
   commitment = SHA256(carrier[0..64]) = H(nf0‖nf1) of the intended action; all gates re-run
   (20/20 acceptance incl. the theft replay, 146/0 red team, 69/0 sweep). v1 (the untagged
   pool, b6ee4196…) is SUPERSEDED — and its minting NFT was burned in the deploy, so it can
   never mint tag blanks; its 750,000 shielded FT remain spendable (state backup
   role2-pool-state-v1-untagged.json).

   ### ✅ THE DURABLE FIX IS DEPLOYED — chipnet-role2-pool-v2-tagged (2026-11-24 PM, blocks 345,467+).
   Hook revision: check 4c (both fuel inputs carry the pool category as MUTABLE NFTs) +
   check 4g (both fuel commitments == SHA256(nf0‖nf1) — the same raw-LE fold as the
   nullifier hash, literally SHA256 of the carrier's first 64 bytes). Program 7,834 B
   (+97 B), drift pin d71851a1…; hook price 37,198 op std / 36,046 cons (524 B of role-2
   code). Gates: acceptance 20/20 (the THEFT replay — a valid proof consuming fuel tagged
   for ANOTHER action — REJECTS at the 4g compare); red team 146 runs / 0 accepted, both
   controls accepted; sweep 69 cases / 0 failed, input 2 binding at 6.00% std, max at-cap
   6,754,094 op = 15.92% cap margin.

   Deployment (runner-free, APECS faucet hot wallet): anchor `480e30ff…` (= the category) →
   mint `5ea499ff…` → deploy `2eaeb97f…` (block 345,467) — state NFT at :0, **the MINTING
   NFT PASSED FORWARD at :1** (v1 burned it — that was WHY v1 could never tag), 100M FT
   supply at :2. Tag-batch `b087507b…`: 32 blank mutable NFTs minted from the minting NFT
   (recreated in the same tx) — the blank pool every lock spends 2 of.

   Full lifecycle, every op = prove (role2-op-witness.mjs, real witness under our ceremony
   zkey) → TAGGED LOCK (pool-refill-role2.mjs: tag = SHA256 of the proved op's carrier,
   stamped into 2 blanks, 15k×2 fuel, FT deposit on out0 for shields) → action
   (pool-op-role2.mjs: complete tagged program VM-ACCEPTED consensus+standard on all 3
   inputs pre-broadcast), each action broadcast ATOMICALLY with its lock (the lock
   unconfirmed; the client rule — theft window ~zero):
   • SHIELD 1,000,000 — lock `97d135f9…` (tag 9b15436a…) + action `9d9aa97a…`, fee 30,000
     sats = 1.067 sat/B, block-confirmed; balance 0 → 1,000,000.
   • TRANSFER (notes 2,3 → 4,5) — lock `5db06be7…` (tag 620e2824…) + action `5262417b…`,
     fee 30,000 sats = 1.063 sat/B; balance 1,000,000.
   • UNSHIELD 250,000 (payout executed, 250,000 FT to the wallet) — lock `70ab2a1f…`
     (tag cec1170e…) + action `e54d19fb…`, fee 29,000 sats = 1.029 sat/B; balance 750,000.
   FT conserved exactly at every step; 2 tag NFTs burned per action (burn-by-omission —
   consensus-proven 3× on chain). Final state: root `1829766…`, balance 750,000, notes at
   tree 6,7 (450,000 + 300,000).

   Fee policy (user directive, recorded): BARE — no fee-market headroom (blocks empty);
   15k×2 fuel covers every real action (~28.1 KB) at 1.03–1.07 sat/B; the prove-first flow
   makes exact per-action sizing possible. Wallet ledger: 310,334 → 168,166 sats (142,168
   total for the v2 chain: deploy chain + 33k blank batch + 3 locks' fuel+fees); the wallet
   also holds this category's 99M FT supply + the 250,000 FT payout.

   Tooling (all committed): pool-deploy-role2.mjs (minting-NFT passthrough, no deploy-time
   fuel), pool-tagbatch-role2.mjs (NEW — mint blanks), pool-refill-role2.mjs (rewritten —
   the TAGGED LOCK: computes the tag from the proved op, mutates 2 blanks, carries the FT
   deposit), pool-op-role2.mjs (tag assertions + tagged VM-eval sources + the atomic
   broadcast path).

   ### FUNDING & TERMINOLOGY (user-clarified 2026-11-24 PM). The funder
   `bchtest:qzmux3gx…` is the APECS FAUCET HOT WALLET (faucet-hot-wallet.json — the
   operational float for the apecs-api Worker's FAUCET_BCH_WIF), NOT a public faucet
   service, and NOT the hushyourmoney chipnet-faucet.json key (bchtest:qzk22…, 0 sats,
   unused). It funded the whole chain as the only funded chipnet wallet we hold runner-free
   (423,000 sats, electrum-verified). Its address appears as sender of every SIGNED step
   (anchor/mint/deploy/locks — the mint's outputs all returned to it); the actions contain
   no wallet at all. EXACT LEDGER: 112,666 sats spent (chain fees + fuel burned by the
   actions + the 10,000-sat state float that stays live on the state NFT); 310,334 sats +
   the 99M FT supply + the 250,000 FT payout remain. One key played three demo roles
   (issuer / operator / demo user) that production must separate; every tooling script
   takes --secrets, so any funded chipnet key can fund future locks. TERMINOLOGY: the
   "supporting"/"refill" transactions ARE the LOCK transactions — each pre-creates the
   fuel/deposit UTXOs at the program locking that the next action spends (the fee
   prepayment: each action burns 32,000 sats of fuel because TXINPUTCOUNT==3 forbids a
   fee input).

   ### PRIVACY SURFACE of the fee model (user-surfaced 2026-11-24 PM). The action spends
   its fuel BY OUTPOINT, so the lock's funder is always on-chain linked to the action.
   Per action: SHIELD — the deposit is public by definition (inherent to every shielded
   pool; the privacy promise lives on the spend side, recipients/values off-chain or in
   commitments); TRANSFER — THE real leak: pv=0, nullifiers preimage-resistant (computed
   from the owner's secret inside the witness — revealing them does not reveal which
   commitments were spent), recipients entirely off-chain, BUT the fee-paying wallet
   reveals the ACTOR (and chains their actions if the address is reused); UNSHIELD — the
   payout is public by design, the fee adds little. ROOT CAUSE: the fee asset (BCH) ≠ the
   shielded asset (FT), so unlike Zcash (fully-shielded z→z pays its fee from shielded
   value via vpub_new, no transparent input at all), a transparent fee source must exist.
   NOT a regression: the §14/v4 shape carried the signed funding input INSIDE the action
   tx (input 6); role 2 at least isolates it in a separate, independently-blendable lock.
   CLIENT RULES (privacy) — CORRECTED per user directive 2026-11-24 PM (CashShuffle
   re-appraisal; the earlier "blend via CashFusion" line was transport-blind):
   (1) baseline: fresh history-free fee address per action; (2) browser-native blending =
   a CASHSHUFFLE-STYLE round (simple relay-based message rounds, IN-BROWSER by design —
   the original shuffle.cash ran it in JS; onion-blinded so the relay/coordinator CANNOT
   learn the input→output mapping — the coordinator-sees critique applies to CashFusion,
   not CashShuffle; its equal-amount-tier weakness is moot for us because fuel outputs are
   uniform 16,000 sats BY CONSTRUCTION); wire spec already in-repo:
   hushyourmoney web/pages/research/coinjoin.vue ("the full CashShuffle wire
   specification", lines 14+334–349); our P2P fusion-over-Nostr harnesses (G1–G3L, EXP-01)
   are the working prototype of this protocol class over WebSocket relays — nito.cash is a
   WEB wallet and current CashFusion runs over TCP+Tor in the desktop client, unreachable
   from a browser; (3) desktop CashFusion remains the battle-tested option for desktop
   wallets only. POOL-NATIVE OPTION: a CashShuffle-style round whose outputs ARE the
   tagged fuel UTXOs (N participants, onion-assignment of 2N uniform outputs, server-blind)
   — composes with deposit tagging: the tag identifies WHICH FUEL OUTPUT the action spent
   (already public via outpoints), never which funder paid for it.
6. ✅ **`worstCaseProof` MEASURED for our key — DONE (2026-11-24, later session).** The snarkjs
   minter exists (`gen-sweep-proofs.mjs`, committed at the repo root: random valid circuit
   witnesses proved against `build/pool_final.zkey`, ~35-50 s per proof on the VM, seeded and
   reproducible) and both liveness sweeps ran under our VK with 64 random REAL proofs (seeds
   `sweep-ours-v1a`/`v1b`, committed as `our-sweep-proofs-a/b.json`):
   - `sweep-ours.mjs` (the PLAIN program, stock sweep flow): **70 cases (5 fixtures + the
     lattice-shifted witness + 64 random), 0 failed** — every case accepted in consensus AND
     standard at prover-sized fills AND at exactly the 10,000 B unlock cap, cap rule
     `op ≤ 7,550,832` holds. Min margins 6.00% std / 6.45% cons; max at-cap op 7,076,392 std
     (input 0, cap margin 11.91%); nq range 99-123 (`v1a unshield #26` hit **nq 123**, above the
     reference sweep's random max of 114 — and liveness held).
   - `pool-sweep.mjs` (the HOOKED program, pool-shaped fills, funded scenarios): **69 cases,
     0 failed** — input 2 (the hook's input) binds at 6.00% std / 6.49% cons (the design
     margin); inputs 0/1 ride at 6.89-8.56% (legitimately empty fillers); max at-cap op
     6,749,569 std on input 2 (cap margin 15.97%).
   - **`worstCaseProof` (bench definition: smallest input-0 standard margin) =
     `sweep-ours-v1a shield #13`** — exported into `our-vectors.json` by the updated
     `export-our.mjs`, closing the gap its own header documented.
   - HONEST LIMIT: the stock trapdoor-forced extremes (every-nibble-15 etc.) are structurally
     unreachable under our VK (no trapdoor for a ceremony zkey; real witnesses cannot hit
     measure-zero statement shapes). Those classes remain measured only under the reference
     VK (stock `sweep.json`); op cost is VK-independent given (statement, witness, fills) —
     identical code layout, fixed-size baked constants — but that transfer is an argument, not
     a measurement. See `REVIEW.md` §6.
   - Incidental validation: the first pool-sweep run REJECTED every big-pv minted unshield —
     check 8 (newBalance ≥ 0) correctly firing on underfunded scenarios (balance was 1000 while
     pv was ~2^40); the fixed sweep funds each case with balance = 1000n + pv. The hook's
     balance rule demonstrably enforces on real proofs, not just fixture #2.
   - New program-bytes facts first recorded: hooked code **7,737 B** (plain 7,309 + 428;
     the priced role-2 slice is 427 B), hooked R sha256 `14ab8983…78b` (65 B), pieces
     3,981/3,756, hooked P2SH32 locking
     `aa208caa897c21a9cd65fd617efec64d06c91f766d72334d3e2c51b96b280ea7b10487`.

## ✅ THE MINTING GUARD — deployed (2026-11-24 PM; adopt block 345,503; first guarded batch block 345,504)

WHY: while the minting NFT sits at a plain P2PKH, the operator key IS the minting policy —
a careless spend burns it (exactly how the v1 pool lost it: not a deliberate burn, just no
passthrough output in the deploy), and a compromised key mints unlimited FT.

THE FIX — a P2SH32 covenant (minting-guard.mjs) that the minting NFT is locked to. The ONLY
possible spend: in0 = the guard UTXO, in1 = operator sats; out0 = the minting NFT RECREATED
at the guard's own locking (read back via UTXOBYTECODE — the guard follows the NFT forever);
out1..K = blanks (category + MUTABLE + EMPTY commitment + 0 FT) at the operator P2PKH;
out[K+1] = ONE tokenless change output at the operator P2PKH; + operator signature (gates
batch TIMING only — anti-griefing, NOT the security boundary).

CONSENSUS-IMPOSSIBLE, FOREVER: burning the minting NFT; minting ANY fungible amount (every
category output is amount-pinned to 0, the change must be tokenless — the 100M supply is
frozen); pre-tagged/wrong-capability blanks; redirecting blanks; substituting another token
at the guard locking (the active input's own category/capability/commitment/amount are
self-checked first); extra inputs/outputs (counts pinned).

GATES: suite 14/14 on the BCH-2026 VM (control accepts; burns, de-guard, all four FT-mint
variants incl. foreign-category-on-change, blank shape/redirect, token substitution, extra
input, no signature — all REJECT). Two landmines en route, both recorded in the source:
pushNum(0) must be OP_0 (0x50 is OP_RESERVED — first run died on it), and OP_SIZE is
NON-POPPING (STATUS finding 1 struck AGAIN — commitment/emptiness checks now compare by
direct byte equality against OP_0, no SIZE). Probe-verified introspection bytes
(probe-cap.mjs): minting = reverse(category)+0x02, mutable = +0x01, none/bare = bare
reversed category, tokenless = empty push; commitments push as-stored; amounts push
minimal. (The probe's FIRST run hit the Buffer-aliasing landmine — the recorded symptom,
per-call alternation, appeared exactly as documented; fresh plain Uint8Arrays fixed it.)

DEPLOYED LIVE, NO REDEPLOY (adoption is a custody upgrade; program/state/notes untouched):
- adopt a5d73b4e… (404 B, block 345,503): minting NFT b087507b:0 → guard aa2066a2….
  Guard: redeem 5,103 B, locking aa2066a238ad4109a3093c34fd4cf9b4167b0058375d4ad1c5cc44cd253d3664f0c187, K=64.
- first guarded batch ad1d7845… (9,830 B, block 345,504): the guard script executed on
  chain — consensus 157,733 op / standard 178,853 op, both ACCEPT — minted 64 blanks
  (reserve now 90 = 45 actions) and passed the minting NFT forward at the guard.
- fee gotcha (recorded): the batch's first broadcast died on min-relay (code 66) — the
  100-B signed-size placeholder underestimates the 5,103-B redeem push; the probe now uses
  the EXACT deterministic unlocking length (65-B sig push + redeem push), BARE 1 sat/B + 600.
- pool-deploy-role2.mjs updated: FUTURE POOLS ARE BORN GUARDED — deploy out1 locks the
  minting NFT straight into the guard.

TOOLING: minting-guard.mjs (builder + 14/14 suite), probe-cap.mjs,
pool-guard-adopt-role2.mjs, pool-tagbatch-role2.mjs (rewritten as the guarded batch — the
only path post-adoption). Blanks remain plain P2PKH UTXOs — the LOCK tool is unchanged.

## ✅ BLANK VENDING — permissionless acquisition LIVE (2026-11-24 night; load block 345,663; buys 345,664/345,666)

THE GAP (user directive): "No automated distribution mechanism is built — that is a BIG problem.
We cannot allow ONE party to CONTROL the use of the pool. There MUST be an efficient and
permissionless way to acquire BLANKS."

THE CONSTRAINT: the deployed minting guard pins every batch-minted blank to the operator's
P2PKH FOREVER — its covenant is self-pinning (out0's locking == the active input's own
UTXOBYTECODE) and immortal, so the LIVE category's mint can never be re-pointed. The
permissionless layer must therefore sit AFTER the mint.

THE FIX — the blank-vending covenant (blank-vending.mjs, suite **18/18** on the BCH-2026 VM,
consensus + standard): a P2SH32 "vending machine" per blank UTXO with NO SIGNATURE anywhere.
Shape: in0 = the machine's blank; in1 = the buyer's TOKENLESS funding input; out0 = the blank
recreated at the FUNDING INPUT'S OWN LOCKING (the blank follows the money); out1 = EXACTLY
priceSats tokenless to the operator's P2PKH; out2 = tokenless change anywhere. The script is
the authorization: pay the exact price, the blank is yours — first-come-first-served, no
permission, no operator involvement per blank. Rejection suite: underpay AND overpay (the
price is exact), payment redirect, token-in-payment, third-party delivery, pre-tagged blank,
wrong capability/category, FT-in-blank, float siphon both directions, token in the funding
input, foreign token at the machine, extra input, wrong output counts, token in change.
Blanks are INERT at a P2PKH (they authorize nothing alone — actions still need proof
knowledge of notes + tags + the user's own sats), so blank inflation is NOT value inflation;
spam-resistance comes from fees.

LIVE PROOF — the definitive test: load `460a6f2a…` (657 B, block 345,663) put 2 blanks in
the machine AND funded a FRESH OS-CSPRNG stranger key `bchtest:qpes4zff…` (never seen by the
operator) with 50,000 sats in the same tx. The stranger then bought BOTH blanks with ONLY its
own key — buys `bc2c326e…` (block 345,664) and `49b184f5…` (block 345,666), each 487 B, the
vending script executing ON CHAIN (7,545 op consensus / 8,057 op standard, both ACCEPT). The
only signature in each buy tx is the stranger's own. Stranger wallet now: 2 blanks + 45,826
sats — fully equipped for one complete action, acquired with zero permission.

Tooling: blank-vending.mjs (covenant + 18/18 suite), pool-vend-load-role2.mjs (operator loads
N blanks, optionally funds a demo stranger in the same tx; records state.vending),
blank-buy.mjs (buyer-side self-service: rebuilds the covenant from PUBLISHED params, pins the
rebuilt locking against state.vending.locking — source-drift refusal; VM-evals input 0 both
modes pre-broadcast). Machine: locking `aa206b51396304b3bd4e0e9c254f84d1ee80d83a5c7ccaf3750883d00866480d981287`,
redeem 157 B, price 1,000 sats.

The operator's residual discretion is now ONLY stock depth: how many blanks sit in the
machine. Blanks, once bought, are held at the BUYER's P2PKH — resellable, giftable,
postage-stamp transferable — and the machine can be reloaded by anyone the operator sends
blanks to (they can load THEIR OWN vending covenant with the same published script).

Landmines en route (both recorded in source): (1) a fully-passing signature-free covenant
ends with an EMPTY stack unless it pushes its own success bit — all our checks are *VERIFY
(nothing pushed), so the redeem ends with an explicit OP_1; (2) electrum scripthash = SINGLE
sha256 of the locking, byte-reversed — hash256 (double) returns an empty machine; (3) this
libauth's hash160 takes {ripemd160, sha256} objects and encodeCashAddress may return an object
({address}) — both forms handled.

FUTURE-POOL DESIGN OPTION (not deployed): a born-permissionless guard — batch blanks paid to
the funding input's locking (the guard's own in1) and no operator signature; the mint itself
becomes self-service. Only new categories can adopt it (the live guard is immortal); the
vending layer fully serves the live pool.

## 3-OUT V3 — NOTES MANAGEMENT (2026-11-26, later session)

The 3-output circuit (`circuits/pool3.circom`, 184,528 constraints, 2 public
inputs, 112 private inputs) now has a full build + gate + deployment record.
The 2-out generation is untouched: the hook is parameterized by `outs` (2|3),
and the 2-out hooked program rebuilds byte-identically (code sha256
`d71851a1…`, 7,834 B) — the live 2-out pool's tooling still passes its pins.

**Build + gates (all on the apecsdev VM, `BN_VK_FIXTURES=/home/apecs/cov/our-3out.fixtures.json`):**

| Gate | Result |
|---|---|
| Plain sound verifier under the new VK | code 7,310 B sha256 `6ec7ca8e…`; R 65 B; fixture-0 margins 6.46% consensus / 6.01% standard; unlocking 9,313 / 9,243 / 8,763 B |
| Hooked 3-out program (fixture category) | code 7,848 B sha256 `628207b1…`; R 65 B; locking `aa200240…`; role code 804 / 720 / 2,911 B |
| Hook price (201-B carrier) | 39,082 op standard / 37,930 op consensus; 537 B of role-2 code |
| Acceptance | 21/21 (3 controls + 18 rejection classes; the 3-out adds the cm2 carrier tamper) |
| Red team | 146 runs / 0 accepted; both positive controls accepted (`pool-redteam-3out-report.json`) |
| Liveness sweep (full) | **69 cases / 0 failed** — 5 committed fixtures + 64 minted random proofs (seeds `sweep-3out-v1a` / `sweep-3out-v1b`); consensus min margins 7.86% / 8.54% / 6.49% (inputs 0/1/2), standard 7.40% / 8.07% / 6.00%; max at-cap 7,080,373 op (11.86% cap margin); cap rule all true (`pool3-sweep-report.json`) |
| Liveness sweep (5-fixture subset) | 5 cases / 0 failed; min margin 6.00% standard (input 2); at-cap max 6,716,000 op (16.39% cap margin) (`pool3-sweep-fixtures.json`) |

The hook changes: `CARRIER_LEN_3OUT = 201`; the carrier splits
`nf0|nf1|cm0|cm1|cm2|newRoot|pv(8)|sign(1)`; the actionHash preimage grows to
288 bytes (9 fields); the `OP_SIZE` check expects 288. The deposit tag
`SHA256(carrier[0..64])` is unchanged. The 3-out hook uses the same 12 checks;
the added `cm2` split/preimage pushes account for the +1,884 op / +13 B of
role-2 code.

**Tooling added:** `pool-info.mjs` (the hooked build's code/R/locking, since
stock `build.mjs` cannot smoke-test the hook's token shape); `pool-hook.mjs`
`outs` parameter; `pool-tx.mjs` `outs`; `pool-test/pool-redteam/pool-sweep/
pool-cost/pool-op-role2/pool-deploy-role2` `POOL_3OUT=1` / `--3out` paths;
`wallet-consolidate.mjs`, `blank-sweep.mjs`, `token-sats-recover.mjs` (sats
management for the `plain[0]`-only bench scripts). Committed evidence:
`pool-redteam-3out-report.json`, `pool3-sweep-report.json` (69 cases),
`pool3-sweep-fixtures.json` (5 cases), `build.3out-plain.json`,
`our-3out.fixtures.json`, `our-3out-proofs.json`, `our-3out-sweep-a.json`,
`our-3out-sweep-b.json` (the 64 minted proofs).

**Exact sweep command (from `bn-native-sound/`):**
`BN_VK_FIXTURES=/home/apecs/cov/our-3out.fixtures.json POOL_3OUT=1 node
pool-sweep.mjs /home/apecs/cov/pool3-sweep-report.json
/home/apecs/cov/our-3out-sweep-a.json /home/apecs/cov/our-3out-sweep-b.json`.
The minted proofs were produced by `node gen-sweep-proofs-3out.mjs 32
sweep-3out-v1a /home/apecs/cov/our-3out-sweep-a.json` (and `v1b`).

**Deployed 3-out demo pool (chipnet, 2026-11-26):** category
`bc607a96…` (anchor), mint `62d91e4c…`, deploy `2f650791…`; program 7,848 B
sha256 `73cb0ccb…`, locking `aa204a6c…`; guard `aa20e33c…` (K=64); tag batch
`8e3eaf71…` (64 blanks). SHIELD 1,000 `e847ef56…` (28,326 B, 30,000 sats,
1.059 sat/B; out 400+300+300) → TRANSFER `ef64f3dd…` (28,389 B, 30,000 sats,
1.057 sat/B; spends notes 2+3; out 280+210+210); every input VM-ACCEPTED
consensus+standard. Final state root
`3271108787199986663014643111346367083348315666322274808145127686880774309637`,
balance 1,000 FT, notes 300 (index 4) / 280 (5) / 210 (6) / 210 (7), 8 leaves.
The two actions are the note-management proof: one action creates three notes;
the next spends two and creates three with change splitting. Demo only:
1-of-1 setup, public bootstrap in-notes on the first action, no real nullifier
set, no encrypted note delivery; Gate 7 remains mandatory for mainnet.

**New landmines:**
1. `pool-tagbatch-role2.mjs` reads `state.guard` (top-level); the adopt script
   writes it there, but a born-guarded deploy wrote only `outpoints.guard`.
   Fixed in `pool-deploy-role2.mjs` (top-level alias) + the live state file.
2. A token-spending P2PKH signature must include each source output's token
   data in the signing serialization; a tokenless `sourceOutputs` entry
   produces a signature the network rejects with code 16 (Signature must be
   zero for failed CHECK(MULTI)SIG). Fixed in `blank-sweep.mjs` /
   `token-sats-recover.mjs`.
3. `pool-refill-role2.mjs` sizes from `plain[0]` only; the K=64 tag batch and
   the 15k×2 fuel need a single plain UTXO of ~30,400+ sats. Consolidate the
   wallet (and recover blank/demo-token sats) before locking.

---

## FINDING R2-NULLIFIER-DOUBLING — 2026-11-26 (post-gates): the nullifier fold permits a full-balance drain

**Status: MEASURED, PROVEN, NOT BROADCAST.** Valid Groth16 proofs exist that
use ONE note as BOTH in-notes; both verify `snarkjs groth16 verify` against
their own DEPLOYED VKs (`role2-probe-nullifier-doubling-3out.json` and
`role2-probe-drain-2out.json` on the `apecsdev` VM, in `/home/apecs/cov/`,
not committed; both re-verify after copy).

Mechanism: neither `circuits/pool.circom` nor `circuits/pool3.circom` has ANY
equality constraint on `nf` — the same recorded note loads twice; hook check 7
(`pool-hook.mjs:225-228`) is a FOLD `SHA256(oldNull‖nf0‖nf1)` with no
membership test; `nPublic 2` means `oldNull` is not a public input, so the
circuit cannot constrain the set.

Worst case (2-out pool, live): the 450,600-FT note as both in-notes gives
inSum 901,200 ≥ balance 762,400 → **one UNSHIELD action pays out the entire
762,400 FT**. The 3-out pool (700 FT) drains in three actions. The exploit
was NOT executed on chain.

**Scope note for every number on this page:** the acceptance suites (20/20,
21/21), the red teams (146/0) and the sweeps (69/0, 69/69) all used DISTINCT
in-notes — none covers same-note doubling. Those gates stand as measured, but
they do NOT establish double-spend resistance. The v3 nullifier set (membership
proofs in the circuit + a hook check) is the fix; the SMT-depth measurement
decides in-circuit vs hook-level and precedes any ceremony.

**Standing rule until the nullifier set ships: no valued asset may enter any
pool running this hook. Gate 7 is not the only mainnet gate — the nullifier
set is.**

Full record: `hushyourmoney/docs/HANDOFF-2026-11-26-3OUT-NOTES-MANAGEMENT.md`
§12; disclosure on `/research/shielded-pool`; `pool-registry.json`
`knownFindings` on both live role-2 entries.
