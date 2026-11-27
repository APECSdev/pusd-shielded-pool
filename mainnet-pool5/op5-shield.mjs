// op5-shield.mjs — the pool5 SHIELD (pv=4, sign=0): the user's remaining 4 PUSD units enter the
// pool. 8 inputs: 5 steps + state + holdings + the deploy's combined PUSD/BCH-change UTXO (input 7).
// In-notes = the seed notes {1,0}; out-notes {3,2}; holdings 1 -> 5 FT; state R0 -> R1.
// Broadcast gated: requires BROADCAST=1 (default = DRY build + VM-eval only).
import { readFileSync, writeFileSync } from "node:fs"
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
const CATEGORY = pool.category, DEPLOY = pool.deploy
const poolLocking = Buffer.from(pool.poolLocking, "hex")
const metas = JSON.parse(readFileSync(HOME + "/matrix/pool5-metas.json", "utf8"))
const m = metas.shield
const v = JSON.parse(readFileSync(HOME + "/matrix/pool5-shield.json", "utf8"))
const artifact = JSON.parse(readFileSync(HOME + "/matrix/pool5.artifact.json", "utf8"))
const steps = produceTransaction(v.vk, v.proof, v.publicInputs)

const poolCatOnchain = Buffer.from(CATEGORY, "hex").reverse()
const assetOnchain = Buffer.from(PUSD, "hex").reverse()
const bytecode = Buffer.from(artifact.debug.bytecode, "hex")
const redeem = Buffer.concat([Buffer.from([0x20]), poolCatOnchain, bytecode])
const pushData = (d) => d.length <= 75 ? Buffer.concat([Buffer.from([d.length]), d])
  : d.length <= 255 ? Buffer.concat([Buffer.from([0x4c, d.length]), d])
  : Buffer.concat([Buffer.from([0x4d, d.length & 0xff, d.length >> 8]), d])

const contract = new Contract(artifact, [new Uint8Array(poolCatOnchain)], { provider: { network: "chipnet" }, contractType: "p2s" })
const unlocker = contract.unlock.spend(new Uint8Array(assetOnchain), new Uint8Array(Buffer.from(m.nf0, "hex")), new Uint8Array(Buffer.from(m.nf1, "hex")), new Uint8Array(Buffer.from(m.cm0, "hex")), new Uint8Array(Buffer.from(m.cm1, "hex")), new Uint8Array(Buffer.from(m.newMerkleRoot, "hex")), 4n, 0n)
const args = unlocker.generateUnlockingBytecode ? unlocker.generateUnlockingBytecode({ transaction: { version: 2, inputs: [], outputs: [], locktime: 0 }, sourceOutputs: [], inputIndex: 0 }) : unlocker
const witness = Buffer.concat([Buffer.from(args), pushData(redeem)])
console.log("covenant witness:", witness.length, "B | pv=4 sign=0")

// the state commitment chain: old = R0 || 32 zeros (the deploy's), new = R1 || sha256(zeros|nf0|nf1)
const oldNull = Buffer.alloc(32, 0)
const newNull = Buffer.from(sha256(Buffer.concat([oldNull, Buffer.from(m.nf0, "hex"), Buffer.from(m.nf1, "hex")])))
const oldCommitment = Buffer.concat([Buffer.from(m.merkleRoot, "hex"), oldNull])
const newCommitment = Buffer.concat([Buffer.from(m.newMerkleRoot, "hex"), newNull])

const w = wallet(JSON.parse(readFileSync(HOME + "/secrets/mainnet-demo-cycle.json", "utf8")))
const PUSDV = pool.pusdChangeValue, PUSDBYTES = hexToBytes(PUSD)
const STEP_V = 2300, POOL_V = 1000, HOLD_V = 1000
const tx = {
  version: 2,
  inputs: [
    { outpointTransactionHash: hexToBytes(DEPLOY), outpointIndex: 1, unlockingBytecode: hexToBin(steps[0].unlocking), sequenceNumber: 0xffffffff },
    { outpointTransactionHash: hexToBytes(DEPLOY), outpointIndex: 2, unlockingBytecode: hexToBin(steps[1].unlocking), sequenceNumber: 0xffffffff },
    { outpointTransactionHash: hexToBytes(DEPLOY), outpointIndex: 3, unlockingBytecode: hexToBin(steps[2].unlocking), sequenceNumber: 0xffffffff },
    { outpointTransactionHash: hexToBytes(DEPLOY), outpointIndex: 5, unlockingBytecode: hexToBin(steps[3].unlocking), sequenceNumber: 0xffffffff },
    { outpointTransactionHash: hexToBytes(DEPLOY), outpointIndex: 4, unlockingBytecode: hexToBin(steps[4].unlocking), sequenceNumber: 0xffffffff },
    { outpointTransactionHash: hexToBytes(DEPLOY), outpointIndex: 0, unlockingBytecode: new Uint8Array(witness), sequenceNumber: 0xffffffff },
    { outpointTransactionHash: hexToBytes(DEPLOY), outpointIndex: 6, unlockingBytecode: new Uint8Array(witness), sequenceNumber: 0xffffffff },
    { outpointTransactionHash: hexToBytes(DEPLOY), outpointIndex: pool.pusdChangeVout, unlockingBytecode: new Uint8Array(0), sequenceNumber: 0xffffffff },
  ],
  outputs: [
    { lockingBytecode: new Uint8Array(poolLocking), valueSatoshis: BigInt(POOL_V), token: { category: hexToBytes(CATEGORY), amount: 0n, nft: { capability: "mutable", commitment: new Uint8Array(newCommitment) } } },
    { lockingBytecode: hexToBin(steps[0].locking), valueSatoshis: BigInt(STEP_V) },
    { lockingBytecode: hexToBin(steps[1].locking), valueSatoshis: BigInt(STEP_V) },
    { lockingBytecode: hexToBin(steps[2].locking), valueSatoshis: BigInt(STEP_V) },
    { lockingBytecode: hexToBin(steps[4].locking), valueSatoshis: BigInt(STEP_V) },
    { lockingBytecode: hexToBin(steps[3].locking), valueSatoshis: BigInt(STEP_V) },
    { lockingBytecode: new Uint8Array(poolLocking), valueSatoshis: BigInt(HOLD_V), token: { category: PUSDBYTES, amount: 5n } },
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
  { valueSatoshis: BigInt(HOLD_V), lockingBytecode: new Uint8Array(poolLocking), token: { category: PUSDBYTES, amount: 1n } },
  { valueSatoshis: BigInt(PUSDV), lockingBytecode: new Uint8Array(w.lock), token: { category: PUSDBYTES, amount: 4n } },
]

// fee: 1.01 sat/B, rounded up to 100 — set the change so the fee is exact
const inTot = 5 * STEP_V + POOL_V + HOLD_V + Number(PUSDV)
const estSize = 39000
const fee = Math.ceil(estSize * 1.01 / 100) * 100
const change = inTot - (POOL_V + 5 * STEP_V + HOLD_V) - fee
if (change < 500) throw new Error("change too small: " + change)
tx.outputs[7].valueSatoshis = BigInt(change)
console.log("in:", inTot, "| out:", inTot - fee, "| fee:", fee, "| change:", change)

// sign input 7 only (the P2PKH PUSD+BCH input; token data included in its source output)
const preimage = generateSigningSerializationBCH({ inputIndex: 7, sourceOutputs, transaction: tx }, { coveredBytecode: w.lock, signingSerializationType: new Uint8Array([0x41]) })
const sig = bchSchnorrSign(hash256(preimage), w.priv)
const sig65 = new Uint8Array(65); sig65.set(sig); sig65[64] = 0x41
tx.inputs[7].unlockingBytecode = new Uint8Array([65, ...sig65, 33, ...w.pub33])

const hex = binToHex(encodeTransactionBCH(tx))
const decoded = decodeTransactionBCH(hexToBin(hex))
console.log("SHIELD tx:", hex.length / 2, "B | fee:", fee, `(${(fee / (hex.length / 2)).toFixed(4)} sat/B)`)
for (const [label, vmf] of [["consensus", false], ["standard", true]]) {
  const vm = createVirtualMachineBch2026(vmf)
  let ok = true
  for (let i = 0; i < decoded.inputs.length; i++) {
    const st = vm.evaluate({ inputIndex: i, transaction: decoded, sourceOutputs })
    console.log(`  VM ${label} input`, i, ok ? "" : "", st.error ? "FAIL: " + st.error : "OK")
    if (st.error) ok = false
  }
  if (!ok) { console.log("VM FAILURE in", label, "mode — NOT broadcasting"); process.exit(1) }
}
const txid = binToHex(hash256(hexToBin(hex)).reverse())
console.log("SHIELD txid:", txid)
if (process.env.BROADCAST) {
  const e = await connect()
  const acc = await e.call("blockchain.transaction.broadcast", [hex])
  console.log("BROADCAST:", acc)
  e.close()
} else console.log("DRY RUN — not broadcast (set BROADCAST=1 to broadcast)")
