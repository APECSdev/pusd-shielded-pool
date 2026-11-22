<!-- NOTE-CARRIER.md -->

# Note Carrier (NP01) — on-chain encrypted-note delivery for the shielded pool

Status: **design v1 + wallet-side implementation + §7.1 VM-eval EXECUTED**
(`nito.cash` `apps/web/src/lib/pool/carrier.js`, unit-tested; §7.1 run on the
`apecsdev` VirtualBox VM 2026-11-22 — see §7). The live chipnet cross-wallet
demo (§7.2) remains PENDING on runner materials (the `runner` VPS is down
until next week; the live pools' operator note sets live there).

## 1. The problem

Every pool operation so far was a **self-transfer**: one wallet generated and
already knew both output notes. Nothing on chain carries an encrypted note
packet, so a **recipient can never learn a note sent to them** — the pool can
shield/unshield/rotate within one wallet, but it cannot do the one thing a
shielded pool exists for: a private *payment*.

> Confirmed from public chipnet data (2026-11-12, HANDOFF-HUSHYOURMONEY.md §10):
> "neither the covenant args nor any output carries an encrypted note packet …
> The PoC transfers were self-transfers (one wallet generates + knows both
> notes). Cross-wallet delivery still needs a carrier (e.g., OP_RETURN) plus a
> covenant output-tolerance check."

This doc specifies that carrier.

## 2. Wire format

The sender APPENDS one extra output to the pool action transaction (always at
the END — never inserted, so no existing output index shifts):

```
output: { lockingBytecode: OP_RETURN <push payload>, valueSatoshis: 0 }

lockingBytecode (167 bytes):
  0x6a                      OP_RETURN
  0x4c 0xa4                 OP_PUSHDATA1 <164>
  <payload, 164 bytes>

payload (164 bytes):
  [ 0.. 3]  magic "NP01"    0x4e 0x50 0x30 0x31  ('N''P' = Nito Pool, '01' = v1)
  [ 4..35]  ephPub          32-byte PACKED ephemeral BabyJub point
                            (circomlibjs packPoint form — Y coordinate + X sign
                            bit — of the sender's ephSk * Base8)
  [36..163] ct              128-byte ciphertext = plaintext XOR keystream

plaintext (128 bytes):
  value     32-byte big-endian   (note field element — same encoding
  ownerPub  32-byte big-endian    convention as the actionHash preimage
  rho       32-byte big-endian    fields in CIRCUIT-DESIGN.md §7 / COVENANT-DESIGN
  r         32-byte big-endian    §4 step 5)
```

**Sizes/standardness:** 167-byte script, comfortably under the 223-byte
data-carrier ceiling BCH relay policy accepts for OP_RETURN outputs. (The exact
policy limit must be confirmed by the live chipnet broadcast in §7 — UNMEASURED
until then; our 167 B leaves ~56 B of headroom regardless.)

**Coverage:** one packet carries ONE recipient note. The transfer's second
output note (typically the sender's own change) needs NO carrier — the sender
already knows it. Two-foreign-recipient transfers would need two carrier
outputs; the standardness of MULTIPLE OP_RETURN outputs per tx is UNMEASURED —
deferred (see §6).

## 3. Cryptography

ECDH over BabyJub (the pool's own curve — no new primitives):

```
sender:    ephSk <- random field element
           ephPub <- ephSk * Base8                    (packed into the packet)
           ss      <- x( ephSk * ReceiverPoint )      (32-byte BE in the KDF)

receiver:  ss <- x( ReceiverSk * unpack(ephPub) )     (same shared secret)

keystream: block i = SHA256( ss || LE32(i) ), i = 0..3   (128 bytes total)
           ct = plaintext XOR keystream
```

**Recipient identity:** the receiver's DELIVERY POINT is their pool spend key
as a full packed BabyJub point (`sk * Base8`, 32 bytes) — the "address" a
sender is given out-of-band (QR/text; no on-chain registry in the PoC). The
note's circuit-level `ownerPub` is the x-coordinate of that same point —
IDENTICAL to the existing `deriveOwnerPub` convention, so nothing about the
circuit, the note format, or the proof changes. (The sender cannot recover
the full point from the bare x-coordinate without a field sqrt — which is
exactly why the address is the packed point.)

**No MAC — commitment-membership validation instead.** A trial decryption
recomputes `cm = Poseidon(value, ownerPub, rho, r)` and accepts the note only
if `cm` is a KNOWN pool leaf (Zcash-style note detection). A wrong key or a
tampered packet yields a `cm` that matches no real leaf with overwhelming
probability; the scan returns null and moves on. The 128-byte plaintext is
high-entropy (three 252-bit secrets + ownerPub), so the keystream reuse window
is per-ephemeral-key: every packet gets a FRESH `ephSk` (no two packets share
a keystream).

**Privacy scope (honest limits):** the carrier hides the note contents from
everyone except the recipient. It does NOT hide: the tx graph (the pool tx is
public), the timing, or the fact that a transfer happened. Amount privacy comes
from the circuit (the carrier's `value` is inside the ciphertext, consistent
with the note the proof commits to — the actionHash already binds `cm` to the
proof on-chain).

## 4. Covenant tolerance — why NO covenant change is required

- `asset-pool.cash` `spend()` constrains ONLY `tx.outputs[0]` (continuity /
  state / conservation) and, on unshield, `tx.outputs[1]` (the public payout).
  It never counts or enumerates outputs — an APPENDED output is invisible to
  every check it performs.
- The 5 verifier inputs use the intra-tx model ("no NFT commitment, no
  `tx.outputs` perpetuation" — COVENANT-DESIGN.md §3a); they introspect
  sibling INPUT witnesses only, never outputs.
- The funding input's Schnorr SIGHASH_ALL signature covers ALL outputs — the
  carrier cannot be stripped or altered after signing without invalidating the
  tx (tamper-evidence comes from the existing signature, not new covenant ops).
- The pool covenant's own op-cost is untouched (measured 65,885–65,981 of a
  ~166,400–168,000 per-input budget, COVENANT-DESIGN.md §7.3) because the
  covenant does not evaluate the carrier at all.

The handoff's required "covenant output-tolerance check" is therefore an
**empirical** full-tx evaluation (the §7 VM run), not a source change. The
eval harness (`eval-pool.mjs`) gained an optional `CARRIER_PACKET_HEX` input to
run exactly that check. **If the VM run surprises us, the fallback is an
explicit carrier whitelist in the covenant (expected unnecessary).**

## 5. Receiver scan (integrates with the note-detection infra)

For every tx that spends a pool covenant UTXO (found via the pool registry /
indexing — the note-detection workstream), the receiver:

1. collects every output's lockingBytecode and calls
   `parseCarrierLockingBytecode()` (magic + format check — skips everything
   else cheaply);
2. for each packet, calls `decryptPacket(packet, sk, leaves)` with the
   wallet's pool spend key and its known leaf set;
3. a non-null result is a received note: `{ value, ownerPub, rho, r, cm,
   leafIndex }` — record it via the wallet's `pool/recordNote` once its
   commitment is on-chain (leaf index confirms).

The scan needs the pool's leaf set — that is exactly what the note-detection
infra (Fulcrum + Chaingraph indexer) maintains, so the carrier lands on top of
that workstream rather than replacing it.

## 6. Deferred (explicitly NOT in v1)

- **Multiple carrier outputs in one tx** (two foreign recipients): BCH
  standardness of multiple OP_RETURN outputs is UNMEASURED; v1 supports the
  dominant one-recipient-plus-change pattern. Verify on chipnet before use.
- **On-chain recipient registry** (finding delivery points): out-of-band
  exchange in the PoC.
- **Sender→recipient memo field**: there is ~0 spare room in a 223 B ceiling
  after a second packet; a memo would go in a SECOND output or a v2 format.
- **Shield-stage carrier:** the first SHIELD's notes are generated by the
  depositor (self-notes) — a carrier is pointless there; it matters from the
  first TRANSFER onward.

## 7. Verification runbook (runner — heavy/chain steps ONLY there)

Per the standing rules: all VM-eval / tx-building / broadcasting happens on
the `runner` VPS (`ssh runner`), VM-evaluating every input before broadcast.

1. **VM-eval with a carrier output** (no chain access needed) — **DONE, PASS
   (2026-11-22, on the `apecsdev` VM** — the `runner` VPS is down until next
   week; user directive to run the eval on the local VM. Environment rebuilt
   there faithfully: `@bitauth/libauth@3.1.0-next.8` (the bench's pin, from
   zk-verifier-bench package.json) + the `compiler-optimizations-8` cashscript
   fork (mr-zwets/cashscript @ `dab3f89`, cloned + tsc-compiled on the VM).
   ```bash
   # executed on the apecsdev VM (~/apps/pusd-shielded-pool):
   CASHSCRIPT_SDK=~/apps/cashscript-fork/packages/cashscript/dist/index.js \
   node eval-pool.mjs artifacts/verifier-vectors.json \
       artifacts/asset-pool.artifact.json build/eval-proofs.json   # baseline
   CARRIER_PACKET_HEX=<real 164-byte packet from the wallet's encryptNote> \
   ...same...                                                  # carrier run
   ```
   **Results:** the BASELINE reproduced the committed
   `artifacts/eval-pool-results.json` byte-for-byte (transfer 65,885/166,400,
   unlocking 167 B; shield 65,893/168,000, 169 B; unshield 65,981/168,000,
   169 B; redeem 222 B; all `accepted: true`), and the CARRIER run (a real NP01
   packet produced by the wallet's `encryptNote`) was IDENTICAL — all three
   paths `accepted: true` at unchanged op-costs. This IS the empirical
   "output-tolerance check": the covenant tolerates the appended carrier
   output with zero cost, exactly as the §4 source analysis predicted.
2. **Live chipnet demo (the blocker's resolution proof):**
   - build a TRANSFER to a SECOND wallet's delivery point (ownerPub = the
     recipient x-coord), appending the carrier output built from
     `encryptNote()`;
   - VM-eval every input; broadcast; wait for confirmation;
   - from the recipient side: fetch the tx, `parseCarrierLockingBytecode` +
     `decryptPacket` with the recipient key and the (updated) leaf set — the
     note MUST decrypt and its `cm` MUST be a pool leaf;
   - then spend that received note (proves end-to-end key/derivation parity
     across two wallets).

## 8. What this deliberately does NOT touch

- `asset-pool.cash` (covenant bytecode — unchanged, 222 B),
- the verifier's 5 inputs (untouched, per COVENANT-DESIGN §3a),
- the circuit / zkey / vkey (the carrier is invisible to the proof; proofs
  remain pool-address-agnostic),
- the nullifier set, conservation, or actionHash binding (all unchanged).
