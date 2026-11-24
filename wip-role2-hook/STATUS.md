# wip-role2-hook — status

**Work in progress. Not reviewed, not deployed.** These files implement the pool rules as a
`bn-native-sound` role-2 `COVENANT` hook (design: `../ROLE2-POOL-HOOK-DESIGN.md`).

## What works

- **The hook compiles into role 2 and the program builds.** `pool-build.mjs` registers the hook
  via `setCovenant` and then runs the stock `build.mjs`; the code blob is generated, and the
  program runs on the BCH-2026 VM.
- **The carrier parsing works.** Output 0 is checked for exact size and prefix and split into
  `nf0‖nf1‖cm0‖cm1‖newRoot‖pv(8)‖sign(1)`; the limbs are decoded and `sign` is range-checked.
- **Every tamper case rejects**, in both consensus and standard mode:
  carrier `newRoot` changed, carrier `pv` changed, carrier `sign` flipped, carrier `nf0` changed.
  So the binding path (preimage → SHA256 → mask → compare to `n1`) is live.
- **`OP_UTXOTOKENCATEGORY` semantics settled empirically** (`probe.mjs`): introspection returns
  the **reverse** of the bytes stored in `Output.token.category`, followed by the capability
  byte. So source outputs carry the *display* order and the hook compares the *reversed* form.

## What does NOT work yet — the honest blocker

The **control** (an honest pool transition with a real proof) rejects. Localized to the
`n0 == stored merkle root` check, and the evidence says the symbolic stack and the runtime stack
are **off by one** at that point:

```
model stack at the check (top→):  sign | pv | newRoot | cm1 | cm0 | nf1 | nf0 | sc5 | sc4 | sc3
runtime stack at the failure    :  <to32LE(n1)> | <32 zero bytes> | <to32LE(n0)> | <64-byte commitment> | …
emitted code                    :  OP_2 OP_PICK   (pick 'stored', model depth 2)
```

`pick('stored')` at model depth 2 lands on the runtime item **one below** `stored` (the 32-byte
`oldNull`, all zeros), so the comparison is `oldNull == n0le` and fails. The same offset explains
why `n0le` came out as `to32LE(n1)` on the earlier run: `pick('n0')` landed one slot off.

I have **not** found the source of the offset. Candidates I have not eliminated:

1. an asymmetry between how `asm.mjs` models a local function's outputs and what `invoke`
   actually pushes — `STMT` is `defLocal('STMT', 1, STMT_OUT.length, …)` and ends with
   `arrangeAbove('__floor', STMT_OUT)`, so the entry stack depends on `arrangeAbove`'s model
   agreeing with its emitted code;
2. one of my own ops being mis-modelled (I checked the obvious ones: `SIZE`, `SPLIT`, `CAT`,
   `BIN2NUM`, `NUM2BIN`, `VERIFY`, `NUMEQUALVERIFY`, `EQUALVERIFY`, `ROLL` — all pop/push as
   declared).

**Deliberately not done:** I did not "fix" this by swapping the `n0`/`n1` picks or by
compensating the depth. That would make the test pass while encoding a stack model I do not
understand — precisely the failure mode this project has already been burned by twice (F6's
omitted equations, the v2 layout bug).

## Files

| file | what it is |
|---|---|
| `pool-hook.mjs` | the hook: 11 checks, carrier parsing, `STATE_INDEX` literal, `p1..p11` marks for tracing |
| `pool-test.mjs` | pool-aware acceptance harness (the stock `vm.mjs` gives source outputs no token), with a per-check tracer and a runtime-stack dump |
| `pool-build.mjs` | registers the hook then imports the stock `build.mjs` |
| `probe.mjs` | settles `OP_UTXOTOKENCATEGORY` byte order |

Run on the apecsdev VM from `chunked/bn254/bn-native-sound/` with
`BN_VK_FIXTURES=/home/apecs/cov/our.fixtures.json`.

## Two harness facts worth keeping

- **libauth's `Output.token.category` is display order; introspection returns it reversed.**
  Getting this backwards fails the category check on every input.
- **The pool stores its merkle root as the 32-byte LE VM-number form** (as `asset-pool.cash` does),
  while the actionHash preimage uses **big-endian** fields. Mixing them up fails the root check.

## Next step

Resolve the one-slot offset before anything else. The cheapest way is to instrument
`arrangeAbove` (or the `STMT` local function) and compare its model with the runtime stack right
at the `invoke` boundary — i.e. find the offset *before* the hook adds any items, then confirm
whether it is upstream or mine.
