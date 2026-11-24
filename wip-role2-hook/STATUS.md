# wip-role2-hook — status

**The role-2 pool hook WORKS: pool-test passes 14/14 under our own VK** — 3 acceptance
controls (transfer pv=0, shield pv=250, unshield pv=400 — the unshield exercises the
conditional payout branch) and 11 rejection classes, with the COMPLETE program (prologue,
STMT decode, graph solo, all 12 hook checks, then the post-hook GT-GLS fold and the final
pairing verify) executing end-to-end. Still WIP: not independently reviewed, not deployed.

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
| `trace-dump.mjs` | per-state stack dump near the failure; FXI env picks the fixture |
| `probe-size.mjs`, `probe-ix.mjs`, `probe-cat2/3.mjs`, `probe-ops.mjs` | opcode semantics probes (pop/push arity, byte orders) |
| `probe-mutate.mjs`, `probe-carrier.mjs`, `probe-when.mjs`, `probe-isolate.mjs`, `probe-proxy.mjs` | the Buffer-aliasing investigation — repro and isolation of finding #1 |
| `probe-fresh.mjs` | single-scenario fresh-process runner (fills + opCost printout) |
| `carrier-hunt.mjs`, `model-diff.mjs`, `pick-diff.mjs`, `map-code.mjs` | divergence-finding instruments (trace vs assembler model vs disassembly) |

Run on the apecsdev VM from `chunked/bn254/bn-native-sound/` with
`BN_VK_FIXTURES=/home/apecs/cov/our.fixtures.json`.

## Open items — 1-3 OF 5 DONE (2026-11-24, same day)

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
4. ⬜ **Independent review** — new bytes are new review (the standing rule).
5. ⬜ **Redeploy** a pool with the covenant logic inside the verifier, one deploy.
6. ⬜ Optional: `worstCaseProof` still UNMEASURED for our key (no snarkjs minter under
   our VK yet — the densless-fixtures trapdoor does not exist for our zkey).
