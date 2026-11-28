# V4H-DEPOSIT-LIVE-2026-11-27 — the "dead pool" diagnosis REFUTED; the user's 100 PUSD deposit is CONFIRMED on mainnet

## The headline

The v4h mainnet pool (`324b1dbf…`, deploy `61022b8b…`) is **ALIVE**. The deposit action
`5b54fb9783806fca229953dd2b3505e2d0cb5927f795611c45d1715dec48316f` — the pv=100 deposit
(the user's first $1, previously "frozen" at the H covenant) — **broadcast and CONFIRMED**
(merkle proof available; verified: out0 the 201-B carrier, out1 the new state NFT at the
program locking, out2 the holdings carrying **100 of the REAL PUSD** `2469acc5…`). The
pool state advanced: balance 0 → 100, root `51483175…`, nullSet 2 keys, notes 3.

**No check-9 fix, no redeploy, no new walks/H/program were ever needed.** The deployed
C-architecture program (the 11-27 build, the three-contribution chain) is correct and
node-compatible end-to-end for the deposit class.

## The real root cause (measured, then fixed)

The previous session's §1 "OUTTOKCOMMIT divergence" was an artifact of a **state-file
off-by-one**: `role2-pool4-state.mainnet-v4h.json` recorded the in5 slot at the lock
`ceb9d18e…` **vout 4** — but vout 4 is the lock's **wallet BCH change** (a P2PKH output,
now spent), while the tokenless in5 the H covenant expects sits at **vout 5** (3,000 sats
at the H locking; verified on chain). Consequences, all now explained:

- The original action spent `ceb9d18e:4` — a **tokenless P2PKH source** — with the
  H-covenant unlocking → the node correctly failed the H script's category/commitment
  compares (`OP_EQUALVERIFY/NUMEQUALVERIFY`, input 2's error message dominated).
- The local VM rehearsal **passed** because the builder synthesizes the source outputs
  from the state file (it assumed in5 = an hLock tokenless 3,000-sat source) — the
  rehearsal never saw the real chain outpoint. **Lesson: the builder's source-synthesis
  trust boundary is the state file; a wrong vout there defeats the entire rehearsal.**
- After vout 4 got spent (by the session's own probe funding), the rebuilt action failed
  node relay with **"Missing inputs"** — the clean giveaway that the outpoints were wrong.
- The fix: `in5.vout = 5, sats = 3000` (backup at
  `role2-pool4-state.mainnet-v4h.json.bak-in5fix`).

## The measurement ladder (all node-verified, all RELAYED)

`mn-ab.mjs` (committed alongside this record) — a lean probe harness: a P2SH32 test
script asserting the length/encoding of the token-commitment introspection pushes, funded
by two ~700-B txs, ONE blank recycled through the whole ladder via P2PKH-carried NFTs:

| probe | assertion | node verdict |
|---|---|---|
| `size 96` | `SIZE(OUTTOKCOMMIT(1)) == 96` on the deposit's real 96-B commitment | **RELAYED (PASS)** |
| `utxosize 96` | `SIZE(UTXOTOKCOMMIT(0)) == 96` (input side) | **RELAYED (PASS)** |

⇒ Both `OP_OUTTOKCOMMIT` and `OP_UTXOTOKCOMMIT` push the **raw 96-B commitment** on
mainnet nodes — identical to the libauth bench VM. The previous session's `ab9.mjs`
"FAILS on the node" conclusion was mis-attributed: its t2 spent the progNFT/hLock outputs
with their covenant redeems in a synthetic 6-input shape, so those inputs failed their own
shape/continuity checks and the rejection was blamed on the SIZE pin.

Probe txs (all confirmed or relaying): t1 `b3319682…`/t2 `9a53583d…` (size 96),
t1 `078ca70c…`/t2 (utxosize 96). ~4,600 sats of fees total.

## The M2 release (role2-proving-assets-v3-v1)

The post-MPC gates passed (sweep **69/0** merged into
`wip-role2-hook/pool-sweep-v3-mpc-report.json`; red team **164/0** in
`pool-redteam-v3-mpc-report.json` — both committed). The GitHub release was created with
4/5 assets (fixtures, SHA256SUMS, wasm, VK — hashes verified against the staging
`~/m2-v4h/`); the 120.8 MB `pool4_final.zkey` upload (sha256 `de7875e3…`) is in flight
(host upstream to GitHub ≈ 30-60 KB/s); publish the draft when it lands.

## Landmines added this session (beyond the V4H handoff's §6)

1. **The state-file off-by-one class**: the refill tool recorded the lock's in5 at the
   change vout. The builder trusts the state — verify every actionInput vout against the
   chain (scriptPubKey + token data) before building.
2. **"Missing inputs" from the node = a spent/nonexistent outpoint**, not a script issue.
3. **libauth's `outpointTransactionHash` is display-order** — `binToHex(hash)` is the
   display txid; reversing it again double-flips (cost me a false "different outpoints!"
   alarm this session).
4. The genesis-witness **layout gate** (from the pool5 links session, same 24 h): the
   fixed offsets 1792/1825 require the 7,904-B unlocking; a proof with `w.selector == 0`
   encodes `genesis[1]` to ZERO bytes and shifts everything — re-roll proofs until the
   layout matches (gate added to gen scripts).

## Where the permanent-pool mission stands now

1. ~~Measure OUTTOKCOMMIT~~ DONE — raw, no divergence.
2. ~~Fix check 9~~ UNNECESSARY.
3. The chipnet dress rehearsal (the standing user order before further mainnet value
   ops) — needs chipnet sats (~30k; the faucet hot wallet holds 5,917).
4. The mainnet lifecycle continuation: TRANSFER (pv=0) and UNSHIELD — needs the next
   action lock (fuel 23,000×2 + walks 2,000×2 + in6 3,000 ≈ 53,000 sats + fees) — the
   wallet is sats-thin after the links + probe work; a ~0.0006 BCH top-up funds one
   action.
5. The user's 5 remaining PUSD base units: 2 at the wallet (the pool5 unshield payout),
   3 shielded in the pool5 old-gen demo pool — the v4h deposit path can absorb the 2
   wallet units in a follow-up deposit op (pv=2) per the user's direction.

## UPDATE (later the same evening): THE FULL LIFECYCLE IS LIVE ON MAINNET + THE CHIPNET REHEARSAL PASSED

**The mandatory chipnet dress rehearsal ran FIRST** (the standing user order; funded by the
chipnet.bch.ninja faucet — 200,000 sats to wallet A via its PoW claim API, tx `62d01ca9…`;
the faucet-claim harness is committed in `mainnet-pool5/`):

- chipnet v4h pool `654d3230…` (deploy `7648c6ca…`, program 8,078 B sha256 `65a3f215…`,
  born-guarded K=16, asset = the chipnet `e56c0a85…` FT, ZERO user value):
  DEPOSIT `5fca6027…` (pv=1,000, balance 0 → 1,000) → TRANSFER `df6e80c0…` (pv=0) →
  UNSHIELD `6c930969…` (pv=200 paid out publicly, balance → 800) — **all three CONFIRMED
  with merkle proofs**.

**The rehearsal reproduced the off-by-one on chipnet** — the same `OP_EQUALVERIFY`
rejection — which allowed fixing it AT THE SOURCE: `pool-refill-role2-v4h.mjs` line 180
wrote the genesis in5 slot at `vout (NO_SLOT ? 4 : 5)` when the real layout is
`(NO_SLOT ? 5 : 6)` (the change output sits BELOW in5 in both shapes). The mainnet state
had been hand-fixed earlier; the tool fix makes every future genesis lock correct.
Backups: `pool-refill-role2-v4h.mjs.bak-in5vout`.

**The mainnet lifecycle then completed under the user's $1:**

| leg | txid | facts |
|---|---|---|
| DEPOSIT | `5b54fb9783806fca229953dd2b3505e2d0cb5927f795611c45d1715dec48316f` | pv=100, balance 0→100, 46,079 B, fee 1.19 sat/B |
| TRANSFER | `63ccd3db592c07c7677deb08e297080ca2e26ed356f7ff9d1158e115778add1b` | pv=0, ASSET 100→100, 46,083 B, fee 1.02 sat/B (lean fuel 21,000) |
| UNSHIELD | `d8a93aa2b6250a8d37d3f9ea587a8ae5a1a61e4f662a4f9f56316bc1d4b8b4f6` | **pv=10 REAL PUSD paid out publicly** (out3 = 1,000 sats + 10 FT), balance → 90, fee 1.003 sat/B |

Final mainnet state: balance 90 (~$0.90 of the user's PUSD shielded), notes 5, nullSet
6 keys, holdings at `d8a93aa2…:2` (90 FT).

**M2 is PUBLISHED**: `role2-proving-assets-v3-v1` (all 5 assets; the 120.8 MB zkey
round-trip re-downloaded and sha256-verified byte-exact `de7875e3…`).

**New fee landmines (mainnet, measured):** the node's dust floor for token-bearing P2PKH
outputs is 1,000 sats (a 600-sat payout died `dust (code 64)`); the action's 1 sat/B
floor interacts with the lock budget — the unshield needed `STATE_FLOAT_SATS=9700`
(payout sats are unpinned by the hook; the state float shave is the clean lever).

— the Hush side, 2026-11-27 (evening session)
