// op5-unshield.mjs — the pool5 UNSHIELD (pv=2, sign=1): REAL PUSD paid out publicly to the demo
// wallet's P2PKH (output 7). 8 inputs: 5 steps + state + holdings + the SHIELD's BCH change (input 7).
// In-notes = the SHIELD's out-notes {3,2} at leaves 2,3; out-notes {2,1}; holdings 5 -> 3 FT.
// Broadcast gated: requires BROADCAST=1 (default = DRY build + VM-eval only).
// Usage: SHIELD_TXID=<txid> [SHIELD_CHANGE=<sats>] [BROADCAST=1] node op5-unshield.mjs
import { readFileSync } from "node:fs"
import { connect, wallet } from "./wallet.mjs"
import { hexToBytes } from "./identity.ts"
import { sha256 } from "@noble/hashes/sha2.js"
import { hash256, encodeTransactionBCH, decodeTransactionBCH, hexToBin, binToHex, createVirtualMachineBch2026, generateSigningSerializationBCH } from "@bitauth/libauth"
import { produceTransaction } from "/home/apecs/zkb/groth16_cashscript/chunked/bn254/densless-msm/transaction.mjs"
const { Contract } = await import("/home/apecs/zkb/tools/node_modules/cashscript/dist/index.js")
import { bchSchnorrSign } from "./txbuild.ts"

const HOME = process.env.HOME
const PUSD = "2469acc5afa4b10cb5b5c04afb89c3a3ffd61c5da9c01e26d00951cae2a02544"
const pool = JSON.parse(readFileSync(HOME + "/matrix/pool5.json", "utf8"))
const CATEGORY = pool.category
const poolLocking = Buffer.from(pool.poolLocking, "hex")
const metas = JSON.parse(readFileSync(HOME + "/matrix/pool5-metas.json", "utf8"))
const sm = metas.shield, m = metas.unshield
const v = JSON.parse(readFileSync(HOME + "/matrix/pool5-unshield.json", "utf8"))
const artifact = JSON.parse(readFileSync(HOME + "/matrix/pool5.artifact.json", "utf8"))
const steps = produceTransaction(v.vk, v.proof, v.publicInputs)

const SHIELD = process.env.SHIELD_TXID
if (!SHIELD) throw new Error("set SHIELD_TXID (the confirmed SHIELD txid)")
const w = wallet(JSON.parse(readFileSync(HOME + "/secrets/mainnet-demo-cycle.json", "utf8")))

// the SHIELD's outputs: 0=state 1-5=steps 6=holdings 7=BCH change (fetch its value live; SHIELD_CHANGE env overrides for rehearsals)
let SHIELD_CHANGE = process.env.SHIELD_CHANGE ? Number(process.env.SHIELD_CHANGE) : null
if (SHIELD_CHANGE === null) {
  const e = await connect()
  const shTx = await e.call("blockchain.transaction.get", [SHIELD, true])
  const changeOut = shTx.vout[7]
  SHIELD_CHANGE = Math.round(changeOut.value * 1e8)
  console.log("SHIELD:", SHIELD, "| change out7:", SHIELD_CHANGE, "sats | confirmations:", shTx.confirmations)
  e.close()
} else console.log("SHIELD (rehearsal):", SHIELD, "| change override:", SHIELD_CHANGE, "sats")

const poolCatOnchain = Buffer.from(CATEGORY, "hex").reverse()
const assetOnchain = Buffer.from(PUSD, "hex").reverse()
const bytecode = Buffer.from(artifact.debug.bytecode, "hex")
const redeem = Buffer.concat([Buffer.from([0x20]), poolCatOnchain, bytecode])
const pushData = (d) => d.length <= 75 ? Buffer.concat([Buffer.from([d.length]), d])
  : d.length <= 255 ? Buffer.concat([Buffer.from([0x4c, d.length]), d])
  : Buffer.concat([Buffer.from([0x4d, d.length & 0xff, d.length >> 8]), d])

const contract = new Contract(artifact, [new Uint8Array(poolCatOnchain)], { provider: { network: "chipnet" }, contractType: "p2s" })
const unlocker = contract.unlock.spend(new Uint8Array(assetOnchain), new Uint8Array(Buffer.from(m.nf0, "hex")), new Uint8Array(Buffer.from(m.nf1, "hex")), new Uint8Array(Buffer.from(m.cm0, "hex")), new Uint8Array(Buffer.from(m.cm1, "hex")), new Uint8Array(Buffer.from(m.newMerkleRoot, "hex")), 2n, 1n)
const args = unlocker.generateUnlockingBytecode ? unlocker.generateUnlockingBytecode({ transaction: { version: 2, inputs: [], outputs: [], locktime: 0 }, sourceOutputs: [], inputIndex: 0 }) : unlocker
const witness = Buffer.concat([Buffer.from(args), pushData(redeem)])
console.log("covenant witness:", witness.length, "B | pv=2 sign=1")

// state chain: old = R1 || newNull1 (the SHIELD's), new = R2 || sha256(newNull1|nf0|nf1)
const oldNull = Buffer.from(sha256(Buffer.concat([Buffer.alloc(32, 0), Buffer.from(sm.nf0, "hex"), Buffer.from(sm.nf1, "hex")])))
const newNull = Buffer.from(sha256(Buffer.concat([oldNull, Buffer.from(m.nf0, "hex"), Buffer.from(m.nf1, "hex")])))
const oldCommitment = Buffer.concat([Buffer.from(m.merkleRoot, "hex"), oldNull])
const newCommitment = Buffer.concat([Buffer.from(m.newMerkleRoot, "hex"), newNull])

const PUSDBYTES = hexToBytes(PUSD)
const STEP_V = 2300, POOL_V = 1000, HOLD_V = 1000, PAYOUT_V = 1000
const tx = {
  version: 2,
  inputs: [
    { outpointTransactionHash: hexToBytes(SHIELD), outpointIndex: 1, unlockingBytecode: hexToBin(steps[0].unlocking), sequenceNumber: 0xffffffff },
    { outpointTransactionHash: hexToBytes(SHIELD), outpointIndex: 2, unlockingBytecode: hexToBin(steps[1].unlocking), sequenceNumber: 0xffffffff },
    { outpointTransactionHash: hexToBytes(SHIELD), outpointIndex: 3, unlockingBytecode: hexToBin(steps[2].unlocking), sequenceNumber: 0xffffffff },
    { outpointTransactionHash: hexToBytes(SHIELD), outpointIndex: 5, unlockingBytecode: hexToBin(steps[3].unlocking), sequenceNumber: 0xffffffff },
    { outpointTransactionHash: hexToBytes(SHIELD), outpointIndex: 4, unlockingBytecode: hexToBin(steps[4].unlocking), sequenceNumber: 0xffffffff },
    { outpointTransactionHash: hexToBytes(SHIELD), outpointIndex: 0, unlockingBytecode: new Uint8Array(witness), sequenceNumber: 0xffffffff },
    { outpointTransactionHash: hexToBytes(SHIELD), outpointIndex: 6, unlockingBytecode: new Uint8Array(witness), sequenceNumber: 0xffffffff },
    { outpointTransactionHash: hexToBytes(SHIELD), outpointIndex: 7, unlockingBytecode: new Uint8Array(0), sequenceNumber: 0xffffffff },
  ],
  outputs: [
    { lockingBytecode: new Uint8Array(poolLocking), valueSatoshis: BigInt(POOL_V), token: { category: hexToBytes(CATEGORY), amount: 0n, nft: { capability: "mutable", commitment: new Uint8Array(newCommitment) } } },
    { lockingBytecode: hexToBin(steps[0].locking), valueSatoshis: BigInt(STEP_V) },
    { lockingBytecode: hexToBin(steps[1].locking), valueSatoshis: BigInt(STEP_V) },
    { lockingBytecode: hexToBin(steps[2].locking), valueSatoshis: BigInt(STEP_V) },
    { lockingBytecode: hexToBin(steps[4].locking), valueSatoshis: BigInt(STEP_V) },
    { lockingBytecode: hexToBin(steps[3].locking), valueSatoshis: BigInt(STEP_V) },
    { lockingBytecode: new Uint8Array(poolLocking), valueSatoshis: BigInt(HOLD_V), token: { category: PUSDBYTES, amount: 3n } },
    { lockingBytecode: new Uint8Array(w.lock), valueSatoshis: BigInt(PAYOUT_V), token: { category: PUSDBYTES, amount: 2n } },
    { lockingBytecode: new Uint8Array(w.lock), valueSatoshis: 0n }, // change — set below
  ],
  locktime: 0,
}
const sourceOutputs = [
  { valueSatoshis: BigInt(STEP_V), lockingBytecode: hexToBin(steps[0].locking) },
  { valueSatoshis: BigInt(STEP_V), lockingBytecode: hexToBin(steps[1].locking) },
  { valueSatoshis: BigInt(STEP_V), lockingBytecode: hexToBin(steps[2].locking) },
  { valueSatoshis: BigInt(STEP_V), lockingBytecode: hexToBin(steps[3].locking) },
  { valueSatoshis: BigInt(STEP_V), lockingBytecode: hexToBin(steps[4].locking) },
  { valueSatoshis: BigInt(POOL_V), lockingBytecode: new Uint8Array(poolLocking), token: { category: hexToBytes(CATEGORY), amount: 0n, nft: { capability: "mutable", commitment: new Uint8Array(oldCommitment) } } },
  { valueSatoshis: BigInt(HOLD_V), lockingBytecode: new Uint8Array(poolLocking), token: { category: PUSDBYTES, amount: 5n } },
  { valueSatoshis: BigInt(SHIELD_CHANGE), lockingBytecode: new Uint8Array(w.lock) },
]

const inTot = 5 * STEP_V + POOL_V + HOLD_V + SHIELD_CHANGE
const estSize = 39100
const fee = Math.ceil(estSize * 1.01 / 100) * 100
const change = inTot - (POOL_V + 5 * STEP_V + HOLD_V + PAYOUT_V) - fee
if (change < 500) throw new Error("change too small: " + change + " — top up the wallet")
tx.outputs[8].valueSatoshis = BigInt(change)
console.log("in:", inTot, "| fee:", fee, "| payout: 2 PUSD @", PAYOUT_V, "sats | change:", change)

const preimage = generateSigningSerializationBCH({ inputIndex: 7, sourceOutputs, transaction: tx }, { coveredBytecode: w.lock, signingSerializationType: new Uint8Array([0x41]) })
const sig = bchSchnorrSign(hash256(preimage), w.priv)
const sig65 = new Uint8Array(65); sig65.set(sig); sig65[64] = 0x41
tx.inputs[7].unlockingBytecode = new Uint8Array([65, ...sig65, 33, ...w.pub33])

const hex = binToHex(encodeTransactionBCH(tx))
const decoded = decodeTransactionBCH(hexToBin(hex))
console.log("UNSHIELD tx:", hex.length / 2, "B | fee:", fee, `(${(fee / (hex.length / 2)).toFixed(4)} sat/B)`)
for (const [label, vmf] of [["consensus", false], ["standard", true]]) {
  const vm = createVirtualMachineBch2026(vmf)
  let ok = true
  for (let i = 0; i < decoded.inputs.length; i++) {
    const st = vm.evaluate({ inputIndex: i, transaction: decoded, sourceOutputs })
    console.log(`  VM ${label} input`, i, st.error ? "FAIL: " + st.error : "OK")
    if (st.error) {
      ok = false
      if (i === 5 || i === 6) {
        const asm = artifact.bytecode.split(" ")
        const trace = vm.debug({ inputIndex: i, transaction: decoded, sourceOutputs })
        const states = Array.isArray(trace) ? trace : trace.states || []
        const bad = states.filter(x => x.error).slice(0, 1)[0] || states[states.length - 1]
        console.log("    DEBUG failing ip:", bad.ip, "| error:", bad.error)
        const ip = Number(bad.ip)
        for (let k = Math.max(0, ip - 10); k <= Math.min(asm.length - 1, ip + 2); k++) console.log("      asm", k, k === ip ? ">>>" : "   ", String(asm[k]).slice(0, 90))
      }
    }
  }
  if (!ok) { console.log("VM FAILURE in", label, "mode — NOT broadcasting"); process.exit(1) }
}
const txid = binToHex(hash256(hexToBin(hex)).reverse())
console.log("UNSHIELD txid:", txid)
if (process.env.BROADCAST) {
  const e2 = await connect()
  const acc = await e2.call("blockchain.transaction.broadcast", [hex])
  console.log("BROADCAST:", acc)
  e2.close()
} else console.log("DRY RUN — not broadcast (set BROADCAST=1 to broadcast)")
