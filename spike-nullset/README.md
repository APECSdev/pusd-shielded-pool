# spike-nullset — the nullifier-set depth measurement (2026-11-26/27)

The SMT-depth spike ordered by the 2026-11-26 handoff §12.5: measure whether a
collision-free sparse Merkle tree keyed by the nullifier (depth ≈ 254) fits
in-circuit (Poseidon) or hook-level (SHA256 in BCH script), BEFORE any ceremony
is scheduled. Full decision record:
`hushyourmoney/docs/NULLIFIER-SET-SPIKE-2026-11-27.md`.

## Verdict (measured)

- **In-circuit (Poseidon SMT, dual-walk insert):** one depth-254 insert =
  263,907 c (2×Poseidon(2)/level at 517 c each). The grafted v3 circuit =
  **743,608 c (4.03× the current 184,528)** — and `snarkjs groth16 setup` is
  **REFUSED by `ppot_0080_18.ptau`** (`743608*2 > 2**18`; pot18 supports
  < 262,144 c; the deepest insert that fits, D ≤ 22, is birthday-broken).
  circomlib's SMTProcessor(254) measures costlier (271,758) than the
  hand-rolled dual-walk.
- **Hook-level (SHA256 SMT in BCH script):** the unrolled dual walk ACCEPTS a
  true witness and REJECTS a tampered sibling/root on the real
  `createVirtualMachineBch2026` VM at D=64 (318,065 op) and D=128 (633,401
  op), always far under the self-funded `(41 + unlockingLen) × 800` budget.
  At D=254 the unrolled script (11,656 B) exceeds the 10,000-B locking cap —
  the production shape is one ~24-B level-body function invoked 1,016× via the
  role-2 program's existing invoke mechanism (~4–6 KB, estimate). Sibling
  witness 8,481 B/nullifier rides a dedicated input.
- **Decision: hook-level set.** The one mandatory circuit revision (deposit
  path + `nf0 ≠ nf1`, ~4 c) stays under pot18 — the ceremony economics do not
  change.

## Files

- `circuits/smt_insert.circom` — the dual-walk SMTInsert(D) template.
- `circuits/pool3_v3null.circom` / `pool3_v3null128.circom` — pool3 grafted with
  the in-circuit option (sequential inserts, 11-field actionHash, nPublic 2).
- `circuits/probe_*.circom` — unit probes (Poseidon2 517 c, Mux1 1 c,
  Num2Bits254 255 c, MerkleProof(20) 10,400 c, SMTInsert 32/128/254,
  SMTProcessor(254) 271,758 c, Sha256(2304) 156,320 c, Sha256(2816) 187,584 c
  → +31,264 c per 512-bit block).
- `gen-spike-inputs.mjs` — builds BOTH circuit inputs from the live 3-out pool
  state (the current-pool3 anchor input + the v3null input), with a 4-walk
  JS-mirror cross-check of the SMT witnesses. Both pass `snarkjs wtns check`.
- `probe-walk-cost.mjs` — the script-side probe: unit op costs, the 0x7f
  semantics discovery (OP_SPLIT), and the unrolled dual walk at D=64/128/254
  with soundness tamper tests, run on the real VM via the bench's `vm.mjs`.
- `run-all.sh` — the full battery (compiles, r1cs info, wtns timings/checks,
  the two pot18 setup refusals). Log: `build/run-all.log` on the VM.

## Re-run (on apecsdev)

```bash
cd ~/zkb/spike-nullset && ./run-all.sh          # circuits + witness + wtns + pot18 refusals
node gen-spike-inputs.mjs 254                    # the v3null witness (4/4 walks)
node probe-walk-cost.mjs 254                     # the script-side walk (needs ../groth16_cashscript/…/vm.mjs)
```

Landmines are recorded in the decision doc §5 — notably OP_PICK = 0x79 (0x74 is
OP_DEPTH), OP_AND equal-length operands, OP_SPLIT's right-on-top order, the
single-cur stack invariant (sib positions D+3−i, key always position 2), and the
JS sibling mask pinning the split bit (`highMask(i)`).
