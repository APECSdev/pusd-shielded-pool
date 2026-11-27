// matrix5-deploy.mjs — pool5 mainnet deployment: genesis -> deploy, RESUMING from the already-relayed
// prep chain. The category anchor = PREP1 0631da2b…:0 (relayed; the category is its txid). A second
// prep (82684496…) relayed during the fee-fix recovery holds the BCH at :1.
// The FIXED covenant (pool5.artifact.json), the 8-input step build (OP_TXINPUTCOUNT==8), an HONEST
// 1-unit seed (notes {1,0} == holdings 1 FT). The deploy spends the user's 5-FT UTXO, keeps 1 unit
// as holdings and returns 4 FT + the BCH change to the wallet in ONE P2PKH output (the SHIELD's
// input 7 — deposit + fee in one UTXO, per the TXINPUTCOUNT==8 shape).
// Broadcast gated: requires BROADCAST=1 (default = DRY build + VM-eval only).
import { readFileSync, writeFileSync } from "node:fs"
import { connect, wallet, buildTx, sign, evaluate } from "./wallet.mjs"
import { hexToBytes } from "./identity.ts"
import { sha256 } from "@noble/hashes/sha2.js"
import { hash256 } from "@bitauth/libauth"
import { produceTransaction } from "/home/apecs/zkb/groth16_cashscript/chunked/bn254/densless-msm/transaction.mjs"

const HOME = process.env.HOME
const PUSD = "2469acc5afa4b10cb5b5c04afb89c3a3ffd61c5da9c01e26d00951cae2a02544"
const ANCHOR = "0631da2b91b7b04d83eecc9b6d764998f2c5b22495fbd34f896141d30e7ee169" // prep1 — THE category
const BCHTX = "8268449692778e7a8a2df77dae3771ba296caa5f146a82f64aeefa221950f6c7"   // prep2 — the BCH tip
const BCHVOUT = 1
const CATEGORY = ANCHOR
const w = wallet(JSON.parse(readFileSync(HOME + "/secrets/mainnet-demo-cycle.json", "utf8")))
const metas = JSON.parse(readFileSync(HOME + "/matrix/pool5-metas.json", "utf8"))
const e = await connect()

// fetch the live values of the two relayed outpoints (never trust a stale listunspent for mempool chains)
const at = await e.call("blockchain.transaction.get", [ANCHOR, true])
const bt = await e.call("blockchain.transaction.get", [BCHTX, true])
const ANCHOR_V = Math.round(at.vout[0].value * 1e8)
const BCH_V = Math.round(bt.vout[BCHVOUT].value * 1e8)
console.log("ANCHOR:", ANCHOR.slice(0, 16), ":0 =", ANCHOR_V, "sats (confirmations:", at.confirmations ?? 0, ")")
console.log("BCH tip:", BCHTX.slice(0, 16), ":", BCHVOUT, "=", BCH_V, "sats (confirmations:", bt.confirmations ?? 0, ")")

// the user's 5-FT UTXO (confirmed, untouched)
const sh = Buffer.from(sha256(w.lock)).reverse().toString("hex")
const tok = u => u.token_data || u.token
const us = await e.call("blockchain.scripthash.listunspent", [sh, "include_tokens"])
const pusd = us.filter(u => tok(u)?.category === PUSD && u.tx_hash === "f4b245097a06bd97ffbb67ecbf398a645fca784c2f2c25bb07c397969e00e159" && u.tx_pos === 0)
if (!pusd.length) throw new Error("the user's 5-FT UTXO not found unspent")
const pusdTotal = BigInt(tok(pusd[0]).amount)
console.log("PUSD anchor UTXO:", pusd[0].tx_hash.slice(0, 16), ":", pusd[0].tx_pos, "=", pusdTotal.toString(), "FT")

// ── GENESIS: mint the mutable NFT carrying the pool5 seed commitment (fee 1000) ──
const rootLE = Buffer.from(metas.seed.rootLE, "hex")
const commitment = new Uint8Array([...rootLE, ...new Uint8Array(32)])
const gIn = ANCHOR_V + BCH_V
const gChange = gIn - 1000 - 1000
const gTx = buildTx({ inputs: [{ txid: ANCHOR, vout: 0 }, { txid: BCHTX, vout: BCHVOUT }], outputs: [
  { lock: w.lock, value: 1000, token: { category: hexToBytes(CATEGORY), amount: 0n, nft: { capability: "mutable", commitment } } },
  { lock: w.lock, value: gChange },
]})
const gSrc = [{ valueSatoshis: BigInt(ANCHOR_V), lockingBytecode: w.lock }, { valueSatoshis: BigInt(BCH_V), lockingBytecode: w.lock }]
sign(gTx, gSrc, w)
const gR = evaluate(gTx, gSrc)
console.log("GENESIS:", gR.txid, "|", gR.hex.length / 2, "B | fee 1000", `(${(1000 / (gR.hex.length / 2)).toFixed(2)} sat/B)`, "| BCH change:", gChange)
if (process.env.BROADCAST) await e.call("blockchain.transaction.broadcast", [gR.hex]); else console.log("  (DRY)")

// ── DEPLOY: state NFT + the 8-input steps + holdings 1 FT + the combined PUSD/BCH change ──
const artifact = JSON.parse(readFileSync(HOME + "/matrix/pool5.artifact.json", "utf8"))
const bytecode = Buffer.from(artifact.debug.bytecode, "hex")
const poolCatOnchain = Buffer.from(CATEGORY, "hex").reverse()
const redeem = Buffer.concat([Buffer.from([0x20]), poolCatOnchain, bytecode])
const poolLocking = Buffer.concat([Buffer.from([0xaa, 0x20]), Buffer.from(hash256(redeem)), Buffer.from([0x87])])
console.log("redeem:", redeem.length, "B | poolLocking: aa20" + Buffer.from(hash256(redeem)).toString("hex").slice(0, 24) + "…87")

const v = JSON.parse(readFileSync(HOME + "/zkb/tools/demo-vector.json", "utf8"))
const steps = produceTransaction(v.vk, v.proof, v.publicInputs)
const STEP_V = 2300, POOL_V = 1000, HOLD_V = 1000
const dIn = 1000n + BigInt(gChange) + BigInt(pusd[0].value)
const dOutFixed = POOL_V + STEP_V * 5 + HOLD_V
const dFee = 1200
const pusdChangeValue = dIn - BigInt(dOutFixed) - BigInt(dFee)
console.log("deploy: in", dIn.toString(), "| out fixed", dOutFixed, "| fee", dFee, "| PUSD-change output (4 FT + " + pusdChangeValue.toString() + " sats)")
if (pusdChangeValue < 45000n) throw new Error("PUSD-change too small to fund the SHIELD fee: " + pusdChangeValue)
// validated layout: 1,2,3 = executors · 4 = terminal · 5 = genesis  (out4=terminal, out5=genesis)
const stepOrder = [0, 1, 2, 4, 3]
const dTx = buildTx({ inputs: [
  { txid: gR.txid, vout: 0 }, { txid: pusd[0].tx_hash, vout: pusd[0].tx_pos }, { txid: gR.txid, vout: 1 },
], outputs: [
  { lock: poolLocking, value: POOL_V, token: { category: hexToBytes(CATEGORY), amount: 0n, nft: { capability: "mutable", commitment } } },
  ...stepOrder.map(i => ({ lock: Buffer.from(steps[i].locking, "hex"), value: STEP_V })),
  { lock: poolLocking, value: HOLD_V, token: { category: hexToBytes(PUSD), amount: 1n } },
  { lock: w.lock, value: Number(pusdChangeValue), token: { category: hexToBytes(PUSD), amount: pusdTotal - 1n } },
]})
const dSrc = [
  { valueSatoshis: 1000n, lockingBytecode: w.lock, token: { category: hexToBytes(CATEGORY), amount: 0n, nft: { capability: "mutable", commitment } } },
  { valueSatoshis: BigInt(pusd[0].value), lockingBytecode: w.lock, token: { category: hexToBytes(PUSD), amount: pusdTotal } },
  { valueSatoshis: BigInt(gChange), lockingBytecode: w.lock },
]
sign(dTx, dSrc, w)
const dR = evaluate(dTx, dSrc)
console.log("DEPLOY:", dR.txid, "|", dR.hex.length / 2, "B | fee", dFee, `(${(dFee / (dR.hex.length / 2)).toFixed(3)} sat/B)`)
if (process.env.BROADCAST) await e.call("blockchain.transaction.broadcast", [dR.hex])
else console.log("  (DRY)")

writeFileSync(HOME + "/matrix/pool5.json", JSON.stringify({
  category: CATEGORY, deploy: dR.txid, poolLocking: poolLocking.toString("hex"),
  rootLE: rootLE.toString("hex"), units: "1", pusdChangeVout: 7,
  pusdChangeValue: pusdChangeValue.toString(),
}, null, 1))
console.log("saved pool5.json", process.env.BROADCAST ? "" : "(DRY — not broadcast)")
e.close()
