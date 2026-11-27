# V4H-SESSION-HANDOFF-2026-11-27 — the OUTTOKCOMMIT divergence, the live mainnet pool, the frozen PUSD, and the path to the three links

**Read FIRST next session.** This is the complete state of the v4h mainnet push
(the "no-issuer" C architecture) at the end of the 2026-11-27 marathon session.

## 1. THE FINDING (measured on mainnet, isolated by on-chain replay)

The v4h deposit action — proven under the final three-contribution zkey, passing
all 7 inputs in BOTH modes on the libauth bench VM — is **rejected by mainnet
nodes (soul-dev, cashnode.bch.ninja, electroncash.dk — all agree, so it is
consensus, not policy) at input 2 (the hook)** with
`mandatory-script-verify-flag-failed (Script failed an OP_EQUALVERIFY/NUMEQUALVERIFY)`.

**Isolation experiments (all committed; harnesses in the bench dir):**
- `check5replay.mjs` (the hook's check-5 H-sequence: `UTXOTOKCOMMIT(2)` on a
  96-B commitment, the double split, BIN2NUM, UTXOTOKAMT==0, stored==n0le):
  **PASSES on the node** ("Extra items left on stack" = my test's missing
  cleanup only). ⇒ **The INPUT-side `OP_UTXOTOKCOMMIT` pushes the raw 96-B
  commitment.**
- `ab9.mjs size 96 / 40` (the check-9 SIZE pin: `OUTTOKCOMMIT(1)` → OP_SIZE →
  NUMEQUALVERIFY): **FAILS on the node.** ⇒ **The OUTPUT-side
  `OP_OUTTOKCOMMIT` does NOT push the raw 96-B commitment. Not 96 B, not 40 B.**
- The walkB script reads out1's commitment via OUTTOKCOMMIT too — the same
  divergence class would hit it at ≥64-B commitments; the v3.1 chipnet pool's
  CONFIRMED lifecycle ran 64-B commitments through OUTTOKCOMMIT on the CHIPNET
  node fine, so the mainnet/chipnet node behavior at 64 B must be MEASURED
  before trusting it.
- Leading hypothesis (UNMEASURED): for commitments longer than the classic
  40-B CHIP limit, the 2026 mainnet node's OUTTOKCOMMIT pushes something
  else (32 B — a hash256 digest of the commitment? a truncated form?).
  **THE MEASUREMENT IS THE FIRST ACTION OF THE NEXT SESSION** (see §5).

## 2. THE LIVE MAINNET POOL (all confirmed in one block)

- anchor `324b1dbfb05c605937f7e68f62210102beacc8b0ece0537e5bde04e90a875814`
  (= the pool category) · mint `f72aec0114299647454664a5d40ac0e3f853aafa649563f72698218e650be7cc` ·
  deploy `61022b8b46087f2a5c5b49ae9782d05a316807726cc078995b2291e500efc944`
  (state NFT at :0, 96-B genesis commitment — verified comLen=96 on chain) ·
  guard batch `4899462528b6d4a43a421520097be1c955ad54545e79245bb65a64279666c9f9`
  (K=16 blanks at the wallet).
- **THIS POOL IS DEAD for actions** (its hook's check-9 is what the node
  rejects; the program is immutable). A NEW deploy with the fixed hook is
  required. Everything else is reusable (see §4).
- Wallet: `bitcoincash:qrqj0azraqskmsyh8fkaj70p0a8lrw20fcnrhvnvh8`
  (mainnet-demo-cycle.json). Blanks: 16. Pool-cat FT: 99,999,500
  (`8d02e1d47d18c7:5`). The deposit lock `ceb9d18e…` (tagged fuel + walks +
  in5 tokenless at H) is unspent and tagged for the EXISTING deposit op
  (`role2-op4-mn-dep.json`) — REUSABLE only if the new pool uses the SAME
  program/walk/H hashes (it will NOT — the hook fix changes them ⇒ re-lock).
- **THE USER'S PUSD:** the first 100 units (1 PUSD) are **FROZEN at the OLD
  H covenant** (`405c3ad558a0b7550cfc1b403ec697952016b995b782ec2b0b62cb3c9a1e877b:2`,
  3,000 sats + 100 FT) — spendable only by an action on the old pool, which the
  node rejects. **DISCLOSED TO THE USER as a loss unless a future path
  recovers it.** The user then sent **$0.05 = 5 base units** (`f4b245097a06bd:0`)
  — **AT NO POINT may these 5 units be locked anywhere except a lock tx whose
  action broadcasts ATOMICALLY, and ONLY after the chipnet rehearsal passes.**

## 3. THE CASCADE (all under the three-contribution chain — Nito's M2 correction, EXECUTED)

- `zkey verify pool4.r1cs ppot_0080_18.ptau pool4_0003_user.zkey` → **ZKey Ok!**
  (zkey de7875e3…; VK `verification_key_user3.json` f6b49cc0…).
- The 5 fixtures re-proved under it (`our-v3-user3-proofs.json`), the fixtures
  file converted (`our-v3-user3.fixtures.json` e74555dd…), the v4h program
  rebuilt (8,078 B, d0252d98… for the synthetic gate pair), **acceptance
  42/42 under the final chain**, **red team 164/0** (both controls accepted),
  the sweep harness validated on the 5 fixtures (the mint of the 64 sweep
  proofs under the final zkey was IN FLIGHT — check `/home/apecs/cov/our-v4h-sweep-{a,b}.json`).
- M2 assets staged at `~/m2-v4h/` on the VM (pool4_final.zkey /
  verification_key_v3.json / pool4.wasm a9b4b03d… unchanged /
  our-v3-user3.fixtures.json + SHA256SUMS).
- The Nito review answered: `docs/V4H-PIVOT-NITO-REVIEW-RESPONSE-2026-11-27.md`
  (their §1 caught a REAL BUG — check 6 must bind the ASSET category in v4h;
  fixed + regression-verified 0023d1ea byte-identical).

## 4. WHAT IS REUSABLE FOR THE NEW POOL (do not redo)

- The **three-contribution zkey/VK/fixtures** — unchanged by any of this.
- The **deposit proof** `role2-op4-mn-dep.json` (pv=100) — binds the genesis
  root (the EMPTY tree — same for any fresh pool), the ASSET category
  (2469acc5… — same), and no in-notes. **BUT the new pool needs pv=5 (the
  user's 5 units), not pv=100 — a fresh ~3-minute witness+prove under
  pool4_0003_user.zkey is required for the real deposit.**
- All harnesses: acceptance 42/42 (`pool-test-v4h.mjs`), red team
  (`pool-redteam-v4h.mjs`), sweep (`pool-sweep-v4h.mjs`), the chain tools
  (`pool-deploy/refill/op-role2-v4h.mjs`), the walk/test/build scripts, the
  opcode-probe set, `ab9.mjs` (the measurement harness), `mnlist/mnstatus/
  mninspect/mnbalance` utilities.

## 5. THE NEXT SESSION, IN ORDER

1. **MEASURE OUTTOKCOMMIT**: wait for a block; the wallet's test-change
   outputs confirm; run `ab9.mjs size <n>` for n ∈ {32, 64, 96, 33…} until it
   RELAYS — the passing n = the actual push length. If 32: the node pushes a
   digest (hash256?) for long commitments — CONFIRM by comparing the push to
   hash256(the 96-B commitment) with an EQUALVERIFY-style probe.
   **Do the same for UTXOTOKCOMMIT at 96 (input side) — the check5replay says
   raw, but confirm the length explicitly.** Also measure at 64 B (the v3.1
   length) — if OUTTOKCOMMIT pushes raw at 64 on MAINNET, a 64-B-commitment
   redesign may avoid the divergence entirely.
2. **FIX CHECK 9** per the measurement:
   - If OUTTOKCOMMIT pushes a digest for >L-commitments: drop the check-9
     H-branch's SIZE/third-field compare (it is REDUNDANT — the balance chain
     is already unforgeable via check-5's input-side read (node-proven raw)
     + check 9h's out2 == newBal pin). Keep the walkB finalNullRoot pin
     WORKING by keeping the commitment ≤ the raw-push length IF the
     measurement says 64 is raw — otherwise redesign walkB's target read.
   - If a full redesign is needed (e.g., balance in the state UTXO's sats
     via OP_UTXOVALUE if it exists): scope it, do it, re-gate.
3. **THE CHIPNET DRESS REHEARSAL — MANDATORY** (the user's standing order after
   the 1-PUSD loss; this was the skip that cost the day): deploy a v4h pool on
   CHIPNET (asset category = the chipnet e56c0a85 FT — wallet A holds
   99,999,000 of it, ZERO user value at risk) and run the FULL lifecycle
   (deposit → transfer → unshield) against the chipnet node. **The chipnet
   deploy needs ~30k sats — the faucet hot wallet is drained (5,917 sats);
   fund it via the APECS faucet service or find another chipnet wallet.**
   NOTHING mainnet moves until this passes.
4. **MAINNET REDEPLOY** with the fixed hook (new walks/H/program — the K=16
   blanks are REUSABLE only if the new pool keeps the same CATEGORY; a new
   anchor = a new category = the guard batch must re-run on the new pool).
5. **THE LIFECYCLE with the user's 5 units**: witness+prove pv=5 → lock (the
   PUSD rides in6, ATOMIC with the action) → op → TRANSFER → UNSHIELD →
   **fill the three XXX links in docs/BITCOIN-CASH-RESEARCH.md**
   (the user's standing order: "when you are done, UPDATE MY POST WITH THE
   LIVE LINKS"). NOTE: with pv=5, the UNSHIELD must be ≤ 5 — plan the split
   (e.g., deposit 5, transfer, unshield 2).
6. The sweep mint status check + the M2 release after the gates.

## 6. LANDMINES LEARNED THIS SESSION (beyond the handoff's list)

- **`Buffer.from(string)` defaults to UTF-8 — passing a hex STRING without
  'hex' silently hashes/compares garbage.** Hit THREE times (the test's
  catDisplay, the hbisect progHash, the testH2 locking).
- The Asm's `pick()` COPIES (does not move); with IF/ELSE both branches
  pushing the same-named item, the model DOUBLE-COUNTS — use arithmetic
  (e.g., `11 - INPUTINDEX`) instead of branches.
- The node's reject messages are OPCODE-SPECIFIC ("Invalid OP_SPLIT range",
  "OP_EQUALVERIFY", "OP_NUMEQUALVERIFY") — bisection via truncating the
  action's inputs (it is SIGNATURE-FREE — tamper-and-rebroadcast is free).
- The refill's change output was initialized to 0n and set LAST — a wrong
  changeIdx pointed the value at in5, leaving a 0-sat dust change ("dust
  (code 64)" — the exact ghost that cost an hour).
- Mainnet nodes reject 1,000-sat P2SH32 outputs whose redeem is large (the
  H pair) — 3,000 sats relayed fine.
- A nohup'd second background job needs its own `cd` (bit us AGAIN).
- /tmp scripts can't resolve the bench's node_modules — write test scripts
  INTO the bench dir.

## 7. THE HONEST TIMELINE GIVEN TO THE USER

Measurement (30–45 min) + fix (1–2 h) + gates (2–4 h, no re-mint) + chipnet
rehearsal (1 h) + mainnet redeploy + lifecycle (~1 h) ⇒ **links in 4–8 hours
from the session start, tomorrow morning at the outside.** The user's 5 units
are spent ONLY inside the atomic lock+action, ONLY after chipnet passes.

— the Hush side, 2026-11-27 (session end).


## 8. PATH A DISCOVERED AT SESSION END: THE OLD-GEN MAINNET POOL — REAL PUSD LINKS IN ~45 MIN

`~/matrix/` (found by the home-wide txid hunt at session end) holds the COMPLETE
2026-11-20 mainnet tooling: prep/genesis/deploy.mjs, op.mjs…op4.mjs (the 7-input
covenant op builders), pool2/3/4.json (the state), wallet.mjs (the demo key), the
covenant artifacts (pool3b.artifact.json = the deployed pool's artifact), and the
verifier pipeline via /home/apecs/zkb/tools (op-meta.json = the live state record:
merkleRoot 49bda9bd… → newMerkleRoot d5ec91ad… — VERIFIED to match the on-chain
state NFT 4fda8a8b…:0's commitment, byte-for-byte, this session).

THE OLD POOL IS ALIVE AND ITS OPS ARE NODE-PROVEN (its TRANSFER 4fda8a8b… confirmed
on mainnet 2026-11-20; its holdings UTXO 4fda8a8b…:6 carries 100 base units of
REAL 2469acc5… PUSD — verified on chain this session).

**THE RUNBOOK (execute with fresh context; ~15 min/op):**
1. Locate the witness-generation inputs on ~/zkb/tools (the input-*.json /
   gen scripts of the 11-20 era; the note secrets for cm0/cm1 of op-meta.json
   — the two 100-unit-split notes — plus the merkle paths against root d5ec91ad).
2. **UNSHIELD FIRST** (does not need the user's new PUSD): witness (in-notes =
   the two current notes, pv=30, sign=1) → snarkjs prove under build/pool_final.zkey
   (the OLD 1-of-1 zkey, 4a4e2543…, on the VM; ~30 s) → produceTransaction
   (VERIFIER_DIR=~/zkb/zk-verifier-bench) → build the 7-input tx (op4.mjs pattern)
   → VM-eval every input both modes → broadcast → the UNSHIELD LINK (REAL PUSD
   PAID OUT publicly from the pool's own 100 units).
3. **SHIELD SECOND** (THE USER'S 5 REAL UNITS, f4b245097a06bd:0): witness (pv=5,
   sign=0, the deposit class) → prove → build (the FT input = the user's UTXO;
   the op carries it per the old-gen SHIELD pattern) → VM-eval → broadcast →
   THE SHIELD LINK (the user's $0.05 enters the pool). **NEVER lock these units
   anywhere except inside the action's own input — the old-gen ops take the FT
   from a P2PKH input directly, no H-covenant, no pre-funding — THIS PATH HAS NO
   FREEZING RISK.**
4. TRANSFER = the existing confirmed 4fda8a8b… (already a mainnet link).
5. Fill the three XXX in docs/BITCOIN-CASH-RESEARCH.md: SHIELD (new) · TRANSFER
   (4fda8a8b) · UNSHIELD (new). HONEST LABELING: these are the earlier-generation
   pool — the post already frames that generation as the prior mainnet demo; the
   v4h links supersede/upgrade in the post when they land.

WHY THIS PATH WAS NOT SEEN EARLIER: the 11-20 session's files were never in any
grep scope (~/matrix was unknown until the home-wide hunt). The old pool's note
secrets were feared lost — they are NOT: the op-meta + the tools are intact, and
the on-chain state matches.


## 9. FINAL PRE-EXECUTION NOTE (session end, post-GO): the note secrets ARE the fixed demo values

The 11-20 mainnet ops ran on the UNCHANGED Nov-13 demo vector (`gen-demo-vector.mjs`
+ `demo-vector.json`, both mtime Nov 13): the TRANSFER 4fda8a8b spent the seeded
tree's notes and created out-notes with the FIXED DEMO SECRETS, recorded verbatim
in the gen script:
- out0 = { value 70,  ownerPub 444, rho 2001, r 6001 }
- out1 = { value 30,  ownerPub 555, rho 2002, r 6002 }
- the current tree root = d5ec91ad… (op-meta.json newMerkleRoot; = the on-chain
  state NFT commitment, verified). The tree = the seed notes (seed256.json,
  ~/zkb/pusd-shielded-pool) + the two appended out-notes (op-meta cm0/cm1).
- The old circuit takes nk as a free witness (the commitment does not bind it) —
  the next op's gen picks the nullifier keys.
- THE UNSHIELD GEN: adapt gen-demo-vector.mjs — in-notes = out0/out1 at their
  indices in the d5ec91ad tree (paths from the reconstructed leaf list), pv=30,
  sign=1; prove under build/pool_final.zkey (the Nov-13 solo zkey 4a4e2543…);
  then op4.mjs's pattern with the covenant unlock (assetOnchain, nf0, nf1, cm0,
  cm1, newRootLE, pv, sign) + the payout output. THE SHIELD GEN: pv=5, sign=0,
  the user's f4b245097a06bd…:0 (5 units) as the FT-carrying input.
- THE POST (user's binding order, twice): **DO NOT CHANGE ANY LANGUAGE OR
  VERBIAGE** — ONLY fill the three XXX slots: SHIELDING (the new 5-unit op),
  TRANSFER (the existing confirmed 4fda8a8b…), UNSHIELDING (the new payout op).
  These links are TEMPORARY — replaced with the v4h lifecycle when it lands.


## 10. PATH A AT TRUE SESSION END: the one remaining unknown + the one ask

EXECUTION STATE (measured, not guessed):
- op4.mjs fully understood: 7-input op (5 verifier steps + state NFT + holdings),
  inputs at the PREV op's vout map (state :0, steps :1-5 (step4 at :4, step3 at :5),
  holdings :6 — RECREATED at the same vouts every op), the covenant unlock takes
  (assetOnchain, nf0, nf1, cm0, cm1, newRootLE, pv, sign); the fee was paid from the
  DEPLOY's fat 10,000-sat step outputs (the TRANSFER's are 2,300 each — NOT enough
  for the next fee). The gen-1 covenant has NO TXINPUTCOUNT pin (the 11-23 disassembly)
  ⇒ an extra BCH funding input is legal.
- THE WALLET IS DRAINED of fee sats (~10-15k left; each op needs ~38k at 1 sat/B
  for its ~38 KB). **THE USER MUST SEND ~0.001 BCH to the demo wallet for the two
  op fees.** ASK THEM FIRST THING.
- pool2/3/4.json = THREE deploy attempts (categories 017a4ff6…, 69c05676…,
  dd1e3506…) — ALL with genesis root 49bda9bd ⇒ the seed tree is a FIXED standard
  the 11-20 session rebuilt each time. The seeds are defined in the iteration
  scripts ~/matrix/matrix2/3/4.mjs or dbg*.mjs — **THE ONE REMAINING UNKNOWN:
  extract the seed-note definitions (values/ownerPub/rho/r/nk) + the exact tree
  leaf list + which two the TRANSFER spent (inSum must equal the "100 conserved").**
- op-meta.json cm0/cm1 (8f1c3070… / ac7fab42…) are NOT the Nov-13 demo out-notes
  (verified: commit(70,444,2001,6001) ≠ 8f1c3070…) ⇒ the 11-20 session generated
  its own notes with its own gen — THE SECRETS ARE IN THE MATRIX SCRIPTS. FIND THEM
  BEFORE WRITING THE UNSHIELD WITNESS. The UNSHIELD then spends the TRANSFER's two
  out-notes (sum 100), pv=30, sign=1; the covenant payout = output 7 (index 7,
  after holdings at 6); the SHIELD brings the user's 5 units (pv=5, sign=0).
- THE POST (binding, thrice): ONLY the three XXX fills — SHIELD (new 5-unit op) ·
  TRANSFER (the confirmed 4fda8a8b…) · UNSHIELD (new payout op). NO language changes.
  Links are TEMPORARY — replaced by the v4h lifecycle when it completes.
