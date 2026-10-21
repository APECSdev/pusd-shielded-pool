# Generalized CashToken Shielding — Why "One assetCategory", and the Path to "Any"

Status: design note. Grounded in `asset-pool.cash`, `circuits/pool.circom`,
`CIRCUIT-DESIGN.md`, and `COVENANT-DESIGN.md`. This answers the recurring judge /
reviewer question directly, then maps the two generalization paths.

> **Q: "Why does the shielded pool hard-code ONE `assetCategory` (PUSD)?"**

**Short answer: it doesn't — not in the circuit, and not in the contract.**
"PUSD-only" is a *deployment* choice (we instantiated one single-asset pool for the
chipnet PoC), not a hard-coded limitation of the cryptography. Both layers are
already asset-agnostic:

- **Circuit** — `assetCategory` is a **private witness**, not a constant. It is fed
  in as two 128-bit limbs (`assetCategoryHi`/`assetCategoryLo`) and bound into the
  `actionHash = Bits2Num(253)(SHA256(nf0|nf1|cm0|cm1|publicValueAbs|publicValueSign|
  assetCategory|newMerkleRoot))`. The R1CS constrains that *some* category is
  committed to the action; it does not care which. The same compiled circuit + the
  same verifying key verify a pool over **any** CashToken category.
- **Covenant** — `contract AssetPool(bytes32 assetCategory)` takes the category as a
  **constructor parameter** (see `COVENANT-DESIGN.md` §7: *"asset-generic; the PUSD
  category is a constructor param, so the same contract serves any CashToken
  category"*). The 222-byte bytecode is identical for every asset; only the
  constructor argument changes.

So the honest framing is: **the PoC is one single-asset shielded pool (PUSD), and
the design already generalizes.** The question is really *which* generalization to
build, and that is a product/protocol decision, not a missing feature.

---

## Why the PoC ships a SINGLE-asset pool (deliberate)

1. **Auditability.** One pinned category makes value-conservation trivial to reason
   about: `sumIn + signedPublic == sumOut` over a single fungible amount, checked
   both in-circuit (range + balance) and by the covenant (`B' == B + dep / B / B − wd`
   via introspection). Adding a second category multiplies the conservation cases a
   reviewer must check.
2. **Clean anonymity sets.** A per-asset pool has an unambiguous anonymity set (all
   PUSD notes). Mixing assets in one tree splits liquidity and complicates
   denomination handling.
3. **Smallest on-chain surface for the PoC.** One category ⇒ one token-conservation
   equation in the covenant, one `tokenCategory` compare per input/output. This is
   what let the covenant stay at **222 B** and ~66k op-cost, ~2.5× under budget.

This mirrors precedent: Tornado Cash deployed **per-denomination** pools; Zcash
started single-asset (ZEC) and only generalized to user-defined assets much later.

---

## Path A — per-asset shielded pools (available NOW, zero code change)

Deploy the **same** `AssetPool` contract + the **same** circuit once **per CashToken
category** (PUSD pool, MUSD pool, any-CashToken pool, …). Each deployment:

- passes its own `assetCategory` constructor arg,
- maintains its own note-commitment Merkle tree + nullifier set (its own anonymity
  set), and
- is verified by the **same** verifying key (the circuit is category-agnostic).

**Cost to support a new shielded asset: a deployment + a registry entry — no new
circuit, no new trusted setup, no covenant change.** This is the recommended
immediate path and is exactly how the wallet's **Nito Vault** will first hold
arbitrary CashTokens privately: one pool instance per category.

Trade-off vs. a single shared pool: N deployments ⇒ N anonymity sets (smaller per
set) and N covenant UTXOs to track. For an early ecosystem this is acceptable and is
the conservative choice.

## Path B — true multi-asset shielded pool (the Nito Vault end-state)

One covenant + one note tree holding **many** CashToken categories, so a user shields
"any CashToken" into a single private balance. This is a **real redesign**, not a
config change. Concretely it requires:

1. **Category inside the note commitment.** Today a note commits to
   `Poseidon(4)(value, ownerPub, rho, r)` — no asset. A multi-asset note must commit
   to `Poseidon(5)(category, value, ownerPub, rho, r)` so each note is bound to one
   asset. (New circuit ⇒ **new trusted setup**.)
2. **Per-category value conservation in-circuit.** The single `sumIn + public ==
   sumOut` equation becomes a per-category balance: for every category `c`,
   `sumIn_c + public_c == sumOut_c`, with `public_c == 0` for all but the
   shielded/unshielded asset of that action. This prevents the pool becoming a
   free PUSD→MUSD converter. It adds a category-multiplex + a balance check per
   input/output note to the R1CS.
3. **Multi-category covenant introspection.** The covenant currently compares
   `tx.inputs[i].tokenCategory == assetCategory(+0x01)` against **one** pinned
   constant. A multi-asset pool UTXO carries tokens of several categories, so the
   covenant must (a) hold the per-category balances in its state NFT commitment and
   (b) enforce that each category is conserved across the transition. The single
   `actionHash` preimage grows to commit to the set of touched categories + their
   deltas.
4. **Denominations / UX.** Mixed-asset pools need per-asset fixed denominations (or
   variable-amount notes with per-asset accounting) to keep the anonymity set from
   fragmenting by amount * asset.

Path B is the natural evolution of the same architecture (note + nullifier +
Merkle-membership + Groth16), and the circuit/covenant groundwork above is written
to make it a **bounded** change: add a `category` field to the note, generalize one
conservation equation to per-category, and widen the covenant's introspection. It is
explicitly **out of scope for the chipnet PoC** (`COVENANT-DESIGN.md` §8) and is the
post-hackathon **Nito Vault** work.

---

## How this maps to the wallet (nito.cash)

| Wallet        | Contents                                        | Mechanism |
| ------------- | ----------------------------------------------- | --------- |
| **Nito Cash** | shielded **spendables** — PUSD (USDCx exploring) | the PUSD pool (this repo), per-asset |
| **Nito Vault**| shielded **savings** — any CashToken             | **Path A now** (per-asset pools) → **Path B** (one multi-asset pool) |
| Naked Cash    | transparent PUSD (+ USDCx exploring)             | plain CashToken UTXOs |
| Naked Vault   | transparent BCH / SOL / CashTokens               | plain UTXOs |

**Nito Cash** is the default wallet and the umbrella alias for all shielded
stablecoins; **Nito Vault** is where generalized shielding lands — per-asset pools
immediately (Path A), evolving into a single multi-asset shielded pool (Path B).
