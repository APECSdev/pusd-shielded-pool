<!-- HANDOFF-HUSHYOURMONEY.md -->

# Handoff — Groth16 Shielded Pool → HushYourMoney team

**Audience:** the [HushYourMoney](https://hushyourmoney.com) team
(`git@github.com:nyusternie/hushyourmoney.git`, Nuxt 3 privacy wallet —
CashShuffle/`shuffle.cash`/`blender.cash` lineage). You are taking **ownership of
the shielded-pool work**. The nito.cash author is moving to Nito Cash UI/UX.

**Goal of this doc:** a complete, self-contained map of what exists, what is proven
on-chain, how to rebuild/re-run every step, and — the headline — **how to generalize
the pool to ANY CashToken asset, not just PUSD.**

**Scope note (why you fit):** HushYourMoney already does BCH privacy (mixing/blending)
and runs a Nuxt 3 app with an Electrum proxy + Fulcrum backend. The shielded pool is
the ZK-native evolution of that: instead of obfuscating the public ledger, sender,
receiver, and amount are removed from it entirely (notes inside a Merkle tree).

---

## 0. The 30-second picture

- **What it is:** the first **shielded pool** for a BCH CashToken (the stand-in PUSD
  token on Chipnet). A **Groth16 zkSNARK** over a Circom joinsplit circuit, verified
  **on-chain in a single BCH transaction** (the BCH 2026 VM upgrade makes this possible).
- **State:** the full lifecycle is **proven on Chipnet** — DEPLOY, SHIELD,
  shielded→shielded TRANSFER, UNSHIELD, and **three transfers in one block**.
- **What's left:** production plumbing — note-detection infra (Fulcrum + Chaingraph),
  wallet/client proving UX, and (your headline) **generalizing to any asset**.
- **Key honesty point:** the cryptography is **already asset-agnostic**. "PUSD-only"
  is a *deployment* choice, not a circuit/contract limit. Generalizing is a
  **product/protocol decision** with a cheap path (per-asset pools, zero code change)
  and a real redesign path (one multi-asset pool). See §6.

---

## 1. Repos & locations

| What | Where | Notes |
| ---- | ----- | ----- |
| Shielded-pool repo (canonical) | `git@github.com:APECSdev/pusd-shielded-pool.git` (local `/Workspace/apecsdev/pusd-shielded-pool`) | the design docs, circuit, covenant, eval scripts, artifacts. **Start here.** |
| Wallet (nito.cash) | `git@github.com:APECSdev/nito.cash.git` | the consumer; UI/UX continues separately. |
| Your repo | `git@github.com:nyusternie/hushyourmoney.git` (local `/Workspace/apecsdev/hushyourmoney`) | Nuxt 3 app, port 3000, Docker/Flux deploy. |
| Heavy-compute VPS ("runner") | `ssh runner` (the `bch-infra`/dev VPS) | all circuit compile / proving / tx-building happens here. **Never on a dev laptop.** |
| Runner workdir | `/home/ubuntu/pusd-shielded-pool` | the live proofs/inputs/metas, built txs, built chains. |
| Runner toolchain | `/home/ubuntu/zkb/` | `cashscript/` (builders), `bench-pusd/` (the on-chain verifier = **VERIFIER_DIR**), `groth16_cashscript/`, `zk-verifier-bench/`. |

### 1a. Compute resources (verified — live SSH, this session)

All shielded-pool heavy compute runs on the **LunaNode** VPS aliased **`runner`**.
Confirmed reachable just now via `ssh runner` (`host=runner ip=172.81.178.35 user=ubuntu`).

| Resource | ssh alias | Host / IP | User | SSH IdentityFile | Role |
| -------- | --------- | --------- | ---- | ---------------- | ---- |
| **LunaNode VPS** | `runner` | `172.81.178.35` | `ubuntu` | `~/.ssh/lunanode_apecs_key` | **ALL heavy compute** — circuit compile, Groth16 setup/proving, tx-building, VM-eval. Hosts `/home/ubuntu/zkb/` + `/home/ubuntu/pusd-shielded-pool/`. |
| **apecsdev VM** (VirtualBox) | `apecsdev` | `127.0.0.1:2222` | `apecs` | `~/.ssh/id_rsa` | Local deploy/build VM (nito.cash prover + Cloudflare deploys via `scripts/deploy-prover.sh`). NOT used for proving. |

Exact `~/.ssh/config` blocks (on the dev host):

```sshconfig
Host runner
  HostName 172.81.178.35
  User ubuntu
  IdentityFile ~/.ssh/lunanode_apecs_key

Host apecsdev
  HostName 127.0.0.1
  Port 2222
  User apecs
  IdentityFile ~/.ssh/id_rsa
```

**LunaNode SSH keys present on the dev host** (`~/.ssh/`): `lunanode_apecs_key`
(← the `runner` key), `lunanode_sansbank_key`, `lunanode_abitsuite_key`
(each with its `.pub`).

> **⚠️ Access caveat (verified).** The `runner` machine is a **LunaNode** VPS — proven by
> its SSH `IdentityFile ~/.ssh/lunanode_apecs_key` (plus the other `lunanode_*` keys on
> the dev host). The `apecsdev` VM is a local VirtualBox guest on the dev host (per
> `nito.cash/AGENTS.md`). **Neither the LunaNode control-panel credentials nor the
> `lunanode_apecs_key` private key are stored in any repo** (keys live only in the dev
> host's `~/.ssh/`). For the HushYourMoney team to access LunaNode directly, the key
> custodian must (a) add a HushYourMoney teammate's SSH **public** key to
> `runner:/home/ubuntu/.ssh/authorized_keys`, and/or (b) share LunaNode panel login /
> spin up a team-accessible instance out-of-band. Do not commit any private key or
> panel credential to git.

> **apecsdev VM resource policy** (from `nito.cash/AGENTS.md`): the dev host has 8 CPUs /
> 31 GB; the APECS VM is capped at 4 CPUs / 8 GB RAM and only ONE VM runs at a time
> (the `Sansbank` VM stays off while APECS runs). Not part of the proving path — listed
> here so the team knows what the `apecsdev` alias is if they encounter it in the
> nito.cash tooling. |

### Docs inside `pusd-shielded-pool` (read in this order)
1. `README.md` — status + on-chain proof links.
2. `CIRCUIT-DESIGN.md` — the Circom/Groth16 joinsplit circuit.
3. `COVENANT-DESIGN.md` — the CashScript pool covenant (state machine + action-hash binding).
4. `GENERALIZED-SHIELDING.md` — **the generalization design (your §6 source of truth).**
5. `CHIPNET.md` — full build record + on-chain worked examples.

---

## 2. The architecture in one page

### 2.1 The circuit (BN254 Groth16, Circom)
File: `circuits/pool.circom` + `circuits/note.circom`. A **2-in/2-out joinsplit**
(Zcash-style) with dummy-note padding. **183,472 constraints** (`build256/pool.r1cs`).

- **Exactly 2 public inputs** (this is the on-chain cost driver — kept minimal):
  `[merkleRoot, actionHash]`.
- **All other logical values are private witnesses packed into**
  `actionHash = Bits2Num(253)(SHA256(nf0 | nf1 | cm0 | cm1 | publicValueAbs | publicValueSign | assetCategory | newMerkleRoot))`
  (each field 32-byte big-endian, digest truncated to 253 bits) and **constrained
  in-circuit**. This is the "Option 2 / Option F" design: it keeps the battle-tested
  2-scalar on-chain verifier unchanged instead of widening it to more public inputs.
- **`assetCategory` is a private witness**, fed as two 128-bit limbs
  (`assetCategoryHi` / `assetCategoryLo`) and bound into the actionHash. The R1CS only
  constrains that *some* category is committed — it does not care which. **← this is
  why the circuit already works for ANY asset (see §6).**
- All in-circuit hashing is **Poseidon** (SNARK-friendly); the on-chain side never
  re-hashes the tree — it only verifies the Groth16 proof.
- Nullifiers are deterministic (`Poseidon(nullifierKey, rho)`) — the anti-double-spend.
- Outputs carry an **encrypted note tag** so a receiver's wallet can trial-decrypt and
  detect incoming notes (Zcash model, adapted to a Chaingraph indexer).

### 2.2 The covenant (CashScript)
File: `asset-pool.cash` → compiles to **222 bytes**, evaluates `accepted: true`,
~66k op-cost (~2.5× under budget).

```c
contract AssetPool(bytes32 assetCategory)   // ← the category is a CONSTRUCTOR PARAM
```

- Holds the pool's CashTokens + carries the pool **state** `{merkleRoot, nullifierSet}`
  in a **CashToken NFT commitment** (mutable).
- A spend requires the Groth16 **verifier transaction** as a sibling input (5-input
  intra-tx pattern), and the covenant enforces the state transition
  `merkleRoot → newMerkleRoot` + appends the two nullifiers.
- **`assetCategory` is compared against introspected `tokenCategory`** — the contract
  bytecode is identical for every asset; only the constructor argument changes
  (`COVENANT-DESIGN.md` §7, *"asset-generic; the PUSD category is a constructor param,
  so the same contract serves any CashToken category"*).

### 2.3 The on-chain verifier (the hard part — already solved)
- The `densless-msm` Groth16 verifier from `mr-zwets/zk-verifier-bench`, wired to **our**
  verifying key. **Proven on the BCH 2026 VM: PASS** — 5/5 valid proofs accepted, 9/9
  mutated public inputs rejected, cross-stage binding BOUND, all 26 maintainer red-team
  runs rejected. **35,626 B in ONE standard transaction**, relayable under default
  mempool policy.
- `vk_x` is recomputed **in-script** (densless-msm pattern) — never accepted as a
  witness — to prevent public-input forgery (the bench red-team's finding).
- One generality fix was upstreamed to **`mr-zwets/groth16_cashscript`** —
  **[PR #26](https://github.com/mr-zwets/groth16_cashscript/pull/26)**
  *"redteam: round-trip number opcodes (OP_1NEGATE, OP_1..OP_16) when re-encoding
  pushes"* (author `nyusternie`; verified via the GitHub API: **state = open**, not
  yet merged). The bench's `redteam.mjs` assumed the genesis selector is always
  `OP_0`, but our proofs use selector `OP_2`; the fix preserves the raw encoded push
  bytes when re-encoding. It is a fixture-dependent generator assumption, **not a
  verifier weakness** — the verifier accepts any selector. **The team must track this
  PR**: until it merges, regenerating the red-team for our key requires the patched
  `redteam.mjs` (`artifacts/redteam.mjs.patched`).

  > Note on attribution: the upstream author goes by the GitHub handle **`mr-zwets`**
  > (repos `groth16_cashscript` and `zk-verifier-bench`). The handle's public GitHub
  > profile does not expose a real name (field is `null`), so this doc cites the
  > verified handle rather than an unverified personal name.

### 2.4 The full transaction shape (one pool op = 1 BCH tx)
Every pool action is a single transaction that spends **6 UTXOs** and recreates them:

```
inputs:  [0]=pool covenant UTXO (token + NFT state)
         [1..3]=EXEC verifier steps   (from the verifier tx)
         [4]=GENESIS step  [5]=TERMINAL step
         [6]=funding/fee P2PKH (Schnorr-signed)
outputs: [0]=pool covenant UTXO (NEW state NFT commitment: newRoot + nullifiers)
         [1..3]=EXEC steps (re-created)
         [4]=GENESIS  [5]=TERMINAL
         [6]=change / public payout (for SHIELD/UNSHIELD)
```

The unlocking script for input 0 calls `spend(nf0,nf1,cm0,cm1,newMerkleRoot,...)`.
The verifier steps' redeem scripts embed the chunked Groth16 verification.

---

## 3. What is PROVEN on-chain (Chipnet) — verified

All on the current **Option B** pool deployment (P2SH32 locking prefix `aa20a458f7…`):

| Action | txid | Block |
| ------ | ---- | ----- |
| DEPLOY + SHIELD | `bd72f1f367cc5e6e8e9f485d84f308ae5e3f80e66b34f82998c7a38eb1698e1a` | 329722 |
| TRANSFER | `b0a488db5b7e9bac07eebc45977523cd0730ddfe078571f2e17135231e30546b` | 329722 |
| UNSHIELD | `e90b9a568d6908bf507e3239cde8b5ef055f9377aa95240d14453669f784717d` | 329736 |
| 3× TRANSFER (one block) | `60fe613e…4273` · `7d89f877…e9e3` · `ebc6e4f9…fc0e` | **329764** |

The three transfers are chained (b spends a's pool output, c spends b's), each
~36.8 KB, no public value moved — **proving many private payments settle in one block**.
Explorer base: `https://chipnet.imaginary.cash/tx/<txid>`.

**Chipnet stand-in token** (PUSD is mainnet-only): category
`479aeebabc682ddb90a3671bffd2a0bd918737de13f19a92231ed36a8580cc11`, 100M fungible
units + minting NFT, genesis tx
`4257dbfb68540cc9afcf569da8e651790c82d3951bdff88f5232a372760ba977` (block 328616).
Mint key (test-only, no value) at `/Workspace/apecsdev/.secrets/pusd-pool-chipnet-mint.json`.

---

## 4. Environment & how to re-run (operations)

**Rule: all heavy compute (circuit compile, Groth16 setup, proving, tx-building,
VM-eval) runs ONLY on the LunaNode `runner` VPS (`172.81.178.35`) — never on a dev
host, and never on the local `apecsdev` VirtualBox VM** (which is reserved for
nito.cash deploy/build, not proving).

### 4.1 Required env var (critical)
```bash
export VERIFIER_DIR=/home/ubuntu/zkb/bench-pusd
```
`VERIFIER_DIR` **must** be set for any `produceTransaction` / `produceWitness` /
VM-eval invocation from `/home/ubuntu/zkb/cashscript/`. Forgetting it is the #1
silent-failure cause (scripts emit the wrong verifier layout or fail to find the vk).

### 4.2 Key runtime pieces on the runner
| Path | Role |
| ---- | ---- |
| `/home/ubuntu/zkb/bench-pusd/` | the on-chain verifier (our vk). `= VERIFIER_DIR`. |
| `/home/ubuntu/zkb/cashscript/packages/cashscript` | the CashScript SDK the builders import. |
| `/home/ubuntu/zkb/cashscript/node_modules/@bitauth/libauth` | tx encode/sign/VM (`createVirtualMachineBch2026`). |
| `/home/ubuntu/zkb/groth16_cashscript/chunked/bn254/densless-msm/transaction.mjs` | `produceTransaction(vk, proof, publicSignals)` → the verifier **steps** (locking/unlocking). |
| `/home/ubuntu/pusd-shielded-pool/` | proofs, inputs, metas, built txs, chains. |
| `/home/ubuntu/node24/bin/node` | the Node 24 runtime used for all scripts. |

### 4.3 The build pipeline for a pool op (per action tag, e.g. `xa`)
1. **Generate the circuit input** (`input-<tag>.json`) + **meta** (`meta-<tag>.json`:
   `nf0LE/nf1LE`, `cm0/cm1`, `newMerkleRootLE`, `nullHashOut`). Scripts `gen-*.mjs`.
2. **Prove** → `proof-<tag>.json` (snarkjs Groth16 against `pool_final.zkey`).
3. **Produce verifier steps** → `<tag>-steps.json` via `produceTransaction(vk, proof,
   publicSignals)` (needs `VERIFIER_DIR`).
4. **Build + VM-evaluate the BCH tx** (e.g. `build-multi-optB.mjs`): assemble the
   6-input/7-output tx, run `createVirtualMachineBch2026` on every input, throw if any
   `error`, then Schnorr-sign the funding input.
5. **Broadcast** via Electrum `blockchain.transaction.broadcast` (chipnet server
   `wss://chipnet.imaginary.cash:50004`).
6. **Confirm** via `blockchain.transaction.get [txid, true]` (confirmations / blockhash).

Reference builders to read (small, single-purpose — keep them that way):
`build-multi-optB.mjs` (the 3-transfer chain), `build-t2-real.mjs` (single transfer,
Option B layout), `bc3.mjs` (broadcast 3), `sameblk.mjs` (verify same block).

### 4.4 Electrum / Fulcrum gotchas (cost time — save it)
- **Scripthash = single SHA-256 of the locking script, byte-reversed** (NOT double-SHA).
  Getting this wrong returns empty history/unspent — a classic silent bug.
- `blockchain.address.listunspent` / `get_balance` **hide token-bearing UTXOs** unless
  you pass the second param `include_tokens` (or `tokens_only`).
- **Spending a token-bearing UTXO requires the source output's token prefix to be
  covered by the sighash** — in libauth set `sourceOutputs[i].token`, else the input
  fails `NULLFAIL` at broadcast.
- The verifier **locking-bytecode layout emitted by `produceTransaction` depends on the
  repo state at generation time**, not on the proof. Re-running it later emits the
  *current* layout for the same proof. (This is exactly how the Option B redeploy
  reused old proofs — see §5.)

---

## 5. Groth16 proof reuse — the rule the team must internalize

A Groth16 proof is bound to exactly **(1) the verifying key** and **(2) the public
inputs** — the *statement* `[merkleRoot, actionHash]`. It is **not** bound to the
pool's address, txid, outpoint, or fee — because the circuit never mixes those in.

**Consequences:**
- ✅ **Reusable across redeployments** at a *new address* as long as the verifying key
  and the note-tree state are the same. This is how the Option B redeploy reused the
  existing `proof-xa/xb/xc.json` — only the **verifier steps** (the on-chain script
  scaffolding, which *did* change layout) were regenerated. No re-proving needed.
- ✅ Rebroadcast of the identical statement.
- ❌ **Double-spend is blocked by the on-chain nullifier set, not by the ZK math.** A
  reused proof for an already-spent note still *mathematically verifies*; the covenant
  rejects it because the nullifier is already recorded.
- ❌ **Stale root** — every transfer advances `merkleRoot`, so a proof can't be replayed
  out of order against a newer root.
- ❌ Different verifying key / different statement → invalid.

**Security model:** replay protection lives in the pool's **on-chain state**
(`{merkleRoot, nullifierSet}`), not in proof "freshness." Same separation Zcash uses.

---

## 6. ★ GENERALIZING to ANY asset — the headline

**Read `GENERALIZED-SHIELDING.md` in full.** This section summarizes and extends it
into an actionable plan.

### 6.1 The crucial fact
"PUSD-only" is a **deployment choice, not a limitation**:

- **Circuit:** `assetCategory` is a **private witness** (two 128-bit limbs), bound into
  the actionHash. The R1CS constrains that *some* category is committed — it does not
  care which. **The same compiled circuit + the same verifying key verify a pool over
  any CashToken category.** No new trusted setup per asset.
- **Covenant:** `contract AssetPool(bytes32 assetCategory)` — the category is a
  **constructor parameter**. The 222-byte bytecode is identical for every asset; only
  the constructor argument changes.

### 6.2 Path A — per-asset shielded pools (available NOW, zero code change)
Deploy the **same** `AssetPool` contract + the **same** circuit once **per CashToken
category** (PUSD pool, MUSD pool, USDCx pool, any-token pool, …). Each deployment:
- passes its own `assetCategory` constructor arg,
- maintains its own note tree + nullifier set (its own anonymity set),
- is verified by the **same** verifying key.

**Cost to add a new shielded asset = one deployment + one registry entry. No new
circuit, no new trusted setup, no covenant change.**

This is the **recommended immediate path** and is how a wallet first holds arbitrary
CashTokens privately: one pool instance per category.

**Trade-off:** N deployments ⇒ N separate anonymity sets (smaller per set) + N covenant
UTXOs to track. Acceptable for an early ecosystem; the conservative choice. (Mirrors
precedent: Tornado deployed per-denomination pools; Zcash started single-asset.)

**To ship a new asset pool (Path A) concretely:**
1. Mint/identify the target CashToken category on the target network.
2. Instantiate the covenant with the new `assetCategory` constructor arg → new P2SH32
   address. (The deploy metadata pattern is in the runner's `deploy-meta*.json`.)
3. Seed the genesis note tree (`seededRootLE`) and fund the pool UTXO + verifier steps.
4. Generate proofs with `assetCategoryHi/Lo` set to the new category (same zkey).
5. Register the pool (address + category + tree root) in a small on-chain/off-chain
   registry so wallets can discover it.

### 6.3 Path B — one multi-asset shielded pool (the end-state redesign)
One covenant + one note tree holding **many** categories, so a user shields "any
CashToken" into a single private balance. This is a **real redesign**, not a config
change. It requires:

1. **Category inside the note commitment.** Today a note commits
   `Poseidon(4)(value, ownerPub, rho, r)` — no asset. A multi-asset note must commit
   `Poseidon(5)(category, value, ownerPub, rho, r)` so each note binds one asset.
   → **new circuit ⇒ new trusted setup.**
2. **Per-category value conservation in-circuit.** The single
   `sumIn + public == sumOut` becomes per-category: for every category `c`,
   `sumIn_c + public_c == sumOut_c`, with `public_c == 0` for all but the
   shielded/unshielded asset of that action. Prevents the pool becoming a free
   PUSD→MUSD converter. Adds a category-mux + a balance check per note to the R1CS.
3. **Multi-category covenant introspection.** The pool UTXO would carry tokens of
   several categories; the covenant must hold per-category balances in its state NFT
   commitment and enforce per-category conservation across the transition. The
   `actionHash` preimage grows to commit the touched categories + their deltas.
4. **Denominations / UX.** Mixed-asset pools need per-asset fixed denominations (or
   variable-amount notes with per-asset accounting) so the anonymity set doesn't
   fragment by amount × asset.

Path B is the natural evolution of the same architecture and is **explicitly out of
scope for the chipnet PoC** (`COVENANT-DESIGN.md` §8). It is the post-handoff
"vault" work.

### 6.4 Recommendation for HushYourMoney
**Start with Path A** — it ships value immediately with zero cryptographic risk
(reuses the proven circuit + verifier + setup). Build the **pool registry** and the
**wallet/indexer plumbing** around it (that's the real work, and it carries over to
Path B). Treat Path B as a follow-up redesign with its own trusted-setup ceremony.

---

## 7. Concrete next-step roadmap for the team

1. **Reproduce the existing proof.** On the `runner` VPS, set `VERIFIER_DIR`, and
   re-run one action end-to-end (input → prove → steps → build → VM-eval → broadcast
   on chipnet). Confirms your environment is sane before changing anything.
2. **Ship a second asset via Path A.** Pick a second CashToken category on chipnet,
   deploy a second pool (§6.2), and run SHIELD/TRANSFER/UNSHIELD against it with the
   *same* verifying key. This is the "generalization works" demo.
3. **Build the pool registry** (address ↔ category ↔ tree-root ↔ anonymity-set) so a
   wallet can discover pools. Start as a JSON/manifest; on-chain registry later.
4. **Note-detection infra.** Stand up Fulcrum + Chaingraph indexing of pool outputs
   and implement the trial-decryption receiver scan (the encrypted note tags). This is
   the missing piece for a usable wallet and is squarely in HushYourMoney's wheelhouse.
5. **Client-side proving UX.** `pool.wasm` + `pool_final.zkey` already exist; wire
   browser proving (the nito.cash side will consume it). HushYourMoney's Nuxt app is a
   natural host to prototype.
6. **(Later) Path B** multi-asset pool + new MPC trusted setup before any mainnet.

## 8. Hard rules / warnings
- **Heavy compute only on the LunaNode `runner` VPS** (`ssh runner`,
  `172.81.178.35`, key `~/.ssh/lunanode_apecs_key`). Never compile/prove on a dev
  host or on the `apecsdev` VirtualBox VM.
- **Always `export VERIFIER_DIR=/home/ubuntu/zkb/bench-pusd`** before producing/verifying.
- **Minimum-diff, logic-preserving edits.** Keep the small single-purpose builder
  scripts small; don't collapse them into monoliths.
- **Small chunks.** Build/verify one transaction (one action) at a time; VM-evaluate
  every input before broadcasting; verify same-block/confirmation before documenting.
- **Full MPC trusted setup is MANDATORY before mainnet.** The chipnet PoC used a
  disclosed local 1-of-1 contribution — fine for PoC, not for production.
- **Don't hand-edit generated artifacts** (`artifacts/asset-pool.artifact.json`,
  `pool_final.zkey`, `verification_key.json`); regenerate them.

## 9. Where things live (quick index)
| Item | Path |
| ---- | ---- |
| Covenant source | `pusd-shielded-pool/asset-pool.cash` |
| Circuit | `pusd-shielded-pool/circuits/{pool,note}.circom` |
| Compiled circuit / vk / zkey / wasm | runner `/home/ubuntu/pusd-shielded-pool/build256/` + repo `artifacts/` |
| On-chain verifier (VERIFIER_DIR) | runner `/home/ubuntu/zkb/bench-pusd/` |
| Tx builders | runner `/home/ubuntu/zkb/cashscript/build-*.mjs` |
| Proofs / metas / built chains | runner `/home/ubuntu/pusd-shielded-pool/` |
| Chipnet token + mint key | `/Workspace/apecsdev/.secrets/pusd-pool-chipnet-mint.json` (test-only) |
| Generalization design | `pusd-shielded-pool/GENERALIZED-SHIELDING.md` |
| Build record / worked examples | `pusd-shielded-pool/CHIPNET.md` |
| Upstream verifier repos | [`mr-zwets/groth16_cashscript`](https://github.com/mr-zwets/groth16_cashscript) + [`mr-zwets/zk-verifier-bench`](https://github.com/mr-zwets/zk-verifier-bench) |
| Our upstreamed fix | [`mr-zwets/groth16_cashscript` PR #26](https://github.com/mr-zwets/groth16_cashscript/pull/26) (open; red-team push round-trip) |

---

*Prepared by the nito.cash author at handoff. All on-chain facts above are confirmed
on BCH Chipnet and reproducible from the runner workdir. When in doubt, re-run a
single small action end-to-end before trusting any larger change.*
