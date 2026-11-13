# PUSD Shielded Pool — BN254 Groth16 Circuit Design

Status: SHIPPED on chipnet (Option B design, on-chain since block 329722).
All on-chain verifier facts are grounded in
`mr-zwets/zk-verifier-bench` @ af53fd2 + `mr-zwets/groth16_cashscript` @ 9b50d34
(red-team-fixed `densless-msm` BN254 entry, PASS on BCH 2026 VM, 5 inputs / 1 tx /
~35.6 KB / ~24.5M op).

> **REVISION 2026-11-13 — public inputs corrected to the shipped design.** The
> original draft proposed **7 public inputs** with `assetCategory` pinned as a
> public input. The SHIPPED Option B design uses **exactly 2 public inputs**
> (`[merkleRoot, actionHash]`) with `assetCategory` as a PRIVATE witness (two
> 128-bit limbs), so the same compiled circuit + verifying key work for ANY
> CashToken category (see `GENERALIZED-SHIELDING.md`). Sections marked
> **[SUPERSEDED]** describe the earlier draft and are retained for history.
> Current facts are grounded in the on-chain Gate 1–6 records and the measured
> redeems (session log in the Hush repo; worked examples in `CHIPNET.md`).

## Goal

One circuit, three operations, all over a single PUSD pool covenant on BCH chipnet:

- SHIELD   : public PUSD CashToken in  -> 1 new note commitment.
- TRANSFER : N note(s) -> M note(s), fully inside the pool (sender/receiver/amount masked).
- UNSHIELD : note(s) -> public PUSD CashToken out.

Groth16 is a FIXED circuit per verifying key: N (max inputs) and M (max outputs)
are constants baked into the trusted setup. We therefore fix a small shape for the
PoC and pad unused slots with dummy (zero-value) notes.

## Public inputs (the values the BCH verifier's vk_x MSM must reproduce)

The on-chain MSM recomputes `vk_x = IC0 + sum_i pub[i] * IC[i+1]`. The number of
public inputs N_pub determines `ic.length = N_pub + 1` and the MSM width. This is
the PRIMARY cost driver on-chain, so we keep N_pub MINIMAL and pack aggressively.

### SHIPPED DESIGN (Option B) — exactly 2 public inputs

On-chain since chipnet block 329722. PoC note shape unchanged: 2 note inputs,
2 note outputs (a "2-2 joinsplit", Zcash-style).

| idx | name       | field repr (Fr)                     | meaning |
|-----|------------|-------------------------------------|---------|
| 0   | merkleRoot | uint256 mod r                       | pool note-commitment tree root (public anchor) |
| 1   | actionHash | Bits2Num(253)(SHA256(preimage))     | binds everything else (see below) |

=> N_pub = 2 public inputs  =>  ic.length = 3  =>  2-scalar on-chain MSM.

`actionHash` preimage = `SHA256(nf0 | nf1 | cm0 | cm1 | publicValueAbs |
publicValueSign | assetCategory | newMerkleRoot)` — eight 32-byte big-endian
fields, truncated to 253 bits to fit BN254 Fr:

- `nf0, nf1` — nullifiers of the two spent notes (anti-double-spend; recorded in
  the covenant's nullifier set)
- `cm0, cm1` — the two new note commitments (recorded on-chain for receiver scanning)
- `publicValueAbs, publicValueSign` — magnitude + sign of the net public asset
  flow (+shield, -unshield, 0 = transfer)
- `assetCategory` — the CashToken category, now a **PRIVATE witness** (two 128-bit
  limbs `assetCategoryHi/Lo`): the same compiled circuit + VK verify a pool over
  ANY category
- `newMerkleRoot` — the post-op tree root the covenant must adopt

The covenant recomputes this SHA-256 on-chain and compares — the on-chain side
never re-hashes the tree (Poseidon stays in-circuit).

Signed handling of publicValue: the circuit range-checks |publicValue| <= MAX and
constrains (sumIn - sumOut) == publicValue. Shield: sumOut - sumIn = -publicValue.
Magnitude and sign travel as two separate 32-byte preimage fields.

### [SUPERSEDED — history] Earlier draft: 7 public inputs

| idx | name          | field repr (Fr)                        | meaning |
|-----|---------------|----------------------------------------|---------|
| 0   | merkleRoot    | uint256 mod r                          | pool note-commitment tree root (public anchor) |
| 1   | nullifier0    | uint256 mod r                          | unique spend tag for input note 0 (anti-double-spend) |
| 2   | nullifier1    | uint256 mod r                          | unique spend tag for input note 1 |
| 3   | commitment0   | uint256 mod r                          | new note commitment (output 0) |
| 4   | commitment1   | uint256 mod r                          | new note commitment (output 1) |
| 5   | publicValue   | int128 (signed, two's-complement in Fr)| net public PUSD moved: +shield, -unshield, 0=transfer |
| 6   | assetCategory | uint256 mod r                          | PUSD CashToken category 0x2469acc5...2544, binds proof to the asset |

=> N_pub = 7 public inputs  =>  ic.length = 8  =>  7-scalar on-chain MSM.

SUPERSEDED by the 2-input Option B packing above: one 32-byte `actionHash`
preimage field replaces six of the seven public inputs, and the category moved
into the private witness (limb split verified against the on-chain ctor push of
transfer tx `b0a488db...546b`).

## Private witnesses (NOT public, never on-chain)

- note[i] = { value, rho, r, skOwner-derived }         for each input note
- merklePath[i], merkleIndex[i]                        membership witness vs merkleRoot
- spendingKey / nullifierKey                           derives nullifier + authorizes spend
- outNote[j] = { value, rho, r, recipientPubKey }      for each output note
- encrypted note tags                                  so the receiver can DETECT (see below)

## In-circuit constraints (R1CS over BN254 Fr)

1. For each input note: recompute its commitment C_i = H(value, rho, r, ownerPub),
   prove membership of C_i in merkleRoot via merklePath (Poseidon hash, cheap in-circuit).
2. nullifier_i = H(nullifierKey, rho)  — deterministic, prevents double-spend.
3. For each output note: commitment_j = H(value, rho, r, recipientPub) — the covenant
   records these on-chain so receivers can scan.
4. Value conservation: sum(in value) + publicValue == sum(out value) (sign per op).
5. Range checks: every note value in [0, MAX]; |publicValue| in [0, MAX].
6. Asset binding: assetCategory is a PRIVATE witness (two 128-bit limbs) hashed
   into the actionHash — NOT pinned as a public constant (supersedes the
   earlier draft).
7. Owner authorization: an EdDSA/Poseidon signature (or key-image check) over the
   tx digest by the input notes' spending key.

## Hash choice (the cost driver)

Poseidon (SNARK-friendly, ~hundreds of constraints per hash) for ALL in-circuit
hashing (commitments, nullifiers, Merkle nodes). NOT SHA256 (SHA256 is ~25k
constraints/hash and would blow up the circuit). The ON-CHAIN side never re-hashes
the tree — it only verifies the Groth16 proof — so Poseidon is safe to use here.
(circomlib provides `poseidon.circom`, `eddsaposeidon.circom`, comparators, mux.)

## Receiver detection (the "not Tornado" requirement)

Each output note carries an encrypted tag = Enc_recipientViewKey(note plaintext),
emitted alongside the commitment. The Chaingraph indexer scans pool outputs; the
receiver's wallet trial-decrypts tags with its view key. Sender/receiver/amount all
stay off the public ledger inside the pool. (This is the Zcash trial-decryption
model adapted to a BCH indexer.)

## Trusted setup

Phase 1: reuse an existing BN254 Powers of Tau (e.g. the Hermez/iden3 `powersOfTau28_hez_final_*`).
Phase 2: circuit-specific (snarkjs `groth16 setup` / `zkey contribute`). For chipnet PoC a
single local contribution is acceptable; mainnet would need a real MPC.

## On-chain integration (adaptation of densless-msm)

- Recompile the verifier for our VK (ic.length=3). **SHIPPED: the 2-scalar
  densless-msm verifier verifies the full pool proof inside ONE standard
  transaction — 35,626 B measured on chipnet — public inputs exactly
  [merkleRoot, actionHash].** (Earlier draft: ic.length=8 / 7-scalar MSM —
  superseded.)
- The pool covenant (CashScript) holds the asset CashTokens + carries { merkleRoot, nullifierSet }
  in an NFT commitment; a spend requires the Groth16 verifier tx as intra-tx
  sibling inputs (6-input/7-output shape: input 0 = pool state, inputs 1-5 =
  verifier steps) whose public inputs are exactly [merkleRoot, actionHash].
  Measured redeem: 347 B (on-chain, transfer tx `b0a488db...546b` input 0).
- vk_x MUST be recomputed in-script (densless-msm pattern) — never accepted as a witness —
  to prevent public-input forgery (the bench red-team finding).
