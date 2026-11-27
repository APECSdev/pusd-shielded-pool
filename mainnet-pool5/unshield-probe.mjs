// unshield-probe.mjs — DRY covenant-logic probe for the live pool4 (pool3b artifact). NEVER broadcasts.
// Q1: does the state path block a pv=30 UNSHIELD?  newBalance = 0 + 30 - 2*1*30 = -30 -> require(newBalance >= 0) should FAIL
//     (state NFT inputs carry tokenAmount = 0 structurally — no pool-category FT exists, minting consumed at deploy).
//     The probe uses the STALE demo proof (op-meta values, root 49bda9bd) with a SYNTHETIC state source commitment
//     matching that old root, so the root check passes and the eval reaches the balance checks. The actionHash check
//     (later in the path) would fail anyway — irrelevant: the balance check fires first.
// Q2: do the 11-13 bench steps accept the 8-input shape (steps + state + holdings + BCH funding)?
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
const pool = JSON.parse(readFileSync(HOME + "/matrix/pool4.json", "utf8"))
const CATEGORY = pool.category, DEPLOY = pool.deploy
const TRANSFER = "4fda8a8b63ff2ef82cc1f5a9ad89bdcbbc86fec254e9c08bb1b874312f6b544f"
const poolLocking = Buffer.from(pool.poolLocking, "hex")
const meta = JSON.parse(readFileSync(HOME + "/zkb/tools/op-meta.json", "utf8"))
const v = JSON.parse(readFileSync(HOME + "/zkb/tools/demo-vector.json", "utf8"))
const artifact = JSON.parse(readFileSync(HOME + "/matrix/pool3b.artifact.json", "utf8"))
const steps = produceTransaction(v.vk, v.proof, v.publicInputs)

const poolCatOnchain = Buffer.from(CATEGORY, "hex").reverse()
const assetOnchain = Buffer.from(PUSD, "hex").reverse()
const bytecode = Buffer.from(artifact.debug.bytecode, "hex")
const redeem = Buffer.concat([Buffer.from([0x20]), poolCatOnchain, bytecode])
const pushData = (d) => d.length <= 75 ? Buffer.concat([Buffer.from([d.length]), d])
  : d.length <= 255 ? Buffer.concat([Buffer.from([0x4c, d.length]), d])
  : Buffer.concat([Buffer.from([0x4d, d.length & 0xff, d.length >> 8]), d])

const contract = new Contract(artifact, [new Uint8Array(poolCatOnchain)], { provider: { network: "chipnet" }, contractType: "p2s" })
const nf0 = Buffer.from(meta.nf0, "hex"), nf1 = Buffer.from(meta.nf1, "hex")
const cm0 = Buffer.from(meta.cm0, "hex"), cm1 = Buffer.from(meta.cm1, "hex")
const newRootLE = Buffer.from(meta.newMerkleRoot, "hex")
// THE PROBE: pv=30, sign=1 (UNSHIELD) — against the LIVE pool3b covenant
const unlocker = contract.unlock.spend(new Uint8Array(assetOnchain), new Uint8Array(nf0), new Uint8Array(nf1), new Uint8Array(cm0), new Uint8Array(cm1), new Uint8Array(newRootLE), 30n, 1n)
const args = unlocker.generateUnlockingBytecode ? unlocker.generateUnlockingBytecode({ transaction: { version: 2, inputs: [], outputs: [], locktime: 0 }, sourceOutputs: [], inputIndex: 0 }) : unlocker
const witness = Buffer.concat([Buffer.from(args), pushData(redeem)])
console.log("covenant witness:", witness.length, "B | pv=30 sign=1")

// state commitment chain: SYNTHETIC old commitment = the stale proof's claimed root (49bda9bd) + zero nullifier
const oldNull = Buffer.alloc(32, 0)
const newNull = Buffer.from(sha256(Buffer.concat([oldNull, nf0, nf1])))
const oldCommitment = Buffer.concat([Buffer.from(meta.merkleRoot, "hex"), Buffer.alloc(32)])
const newCommitment = Buffer.concat([newRootLE, newNull])

// live wallet funding UTXO (the 100,000-sat top-up)
const w = wallet(JSON.parse(readFileSync(HOME + "/secrets/mainnet-demo-cycle.json", "utf8")))
const e = await connect()
const sh = Buffer.from(sha256(w.lock)).reverse().toString("hex")
const us = await e.call("blockchain.scripthash.listunspent", [sh, "include_tokens"])
const tok = u => u.token_data || u.token
const fund = us.filter(u => !tok(u) && u.value === 100000).sort((a, b) => b.value - a.value)[0]
if (!fund) throw new Error("no 100000-sat funding UTXO")
console.log("funding:", fund.tx_hash, ":", fund.tx_pos, "=", fund.value)
e.close()

const STEP_V = 2300, POOL_V = 1000, HOLD_V = 1000, PAYOUT_V = 1000, FUND_V = fund.value
const tx = {
  version: 2,
  inputs: [
    { outpointTransactionHash: hexToBytes(TRANSFER), outpointIndex: 1, unlockingBytecode: hexToBin(steps[0].unlocking), sequenceNumber: 0xffffffff },
    { outpointTransactionHash: hexToBytes(TRANSFER), outpointIndex: 2, unlockingBytecode: hexToBin(steps[1].unlocking), sequenceNumber: 0xffffffff },
    { outpointTransactionHash: hexToBytes(TRANSFER), outpointIndex: 3, unlockingBytecode: hexToBin(steps[2].unlocking), sequenceNumber: 0xffffffff },
    { outpointTransactionHash: hexToBytes(TRANSFER), outpointIndex: 5, unlockingBytecode: hexToBin(steps[3].unlocking), sequenceNumber: 0xffffffff },
    { outpointTransactionHash: hexToBytes(TRANSFER), outpointIndex: 4, unlockingBytecode: hexToBin(steps[4].unlocking), sequenceNumber: 0xffffffff },
    { outpointTransactionHash: hexToBytes(TRANSFER), outpointIndex: 0, unlockingBytecode: new Uint8Array(witness), sequenceNumber: 0xffffffff },
    { outpointTransactionHash: hexToBytes(TRANSFER), outpointIndex: 6, unlockingBytecode: new Uint8Array(witness), sequenceNumber: 0xffffffff },
    { outpointTransactionHash: hexToBytes(fund.tx_hash), outpointIndex: fund.tx_pos, unlockingBytecode: new Uint8Array(0), sequenceNumber: 0xffffffff },
  ],
  outputs: [
    { lockingBytecode: new Uint8Array(poolLocking), valueSatoshis: BigInt(POOL_V), token: { category: hexToBytes(CATEGORY), amount: 0n, nft: { capability: "mutable", commitment: new Uint8Array(newCommitment) } } },
    { lockingBytecode: hexToBin(steps[0].locking), valueSatoshis: BigInt(STEP_V) },
    { lockingBytecode: hexToBin(steps[1].locking), valueSatoshis: BigInt(STEP_V) },
    { lockingBytecode: hexToBin(steps[2].locking), valueSatoshis: BigInt(STEP_V) },
    { lockingBytecode: hexToBin(steps[4].locking), valueSatoshis: BigInt(STEP_V) },
    { lockingBytecode: hexToBin(steps[3].locking), valueSatoshis: BigInt(STEP_V) },
    { lockingBytecode: new Uint8Array(poolLocking), valueSatoshis: BigInt(HOLD_V), token: { category: hexToBytes(PUSD), amount: 70n } },
    { lockingBytecode: new Uint8Array(w.lock), valueSatoshis: BigInt(PAYOUT_V), token: { category: hexToBytes(PUSD), amount: 30n } },
    { lockingBytecode: new Uint8Array(w.lock), valueSatoshis: BigInt(FUND_V - 40000), },
  ],
  locktime: 0,
}
// sign input 7 only (P2PKH funding)
const sourceOutputs = [
  { valueSatoshis: BigInt(STEP_V), lockingBytecode: hexToBin(steps[0].locking) },
  { valueSatoshis: BigInt(STEP_V), lockingBytecode: hexToBin(steps[1].locking) },
  { valueSatoshis: BigInt(STEP_V), lockingBytecode: hexToBin(steps[2].locking) },
  { valueSatoshis: BigInt(STEP_V), lockingBytecode: hexToBin(steps[3].locking) },
  { valueSatoshis: BigInt(STEP_V), lockingBytecode: hexToBin(steps[4].locking) },
  { valueSatoshis: BigInt(POOL_V), lockingBytecode: new Uint8Array(poolLocking), token: { category: hexToBytes(CATEGORY), amount: 0n, nft: { capability: "mutable", commitment: new Uint8Array(oldCommitment) } } },
  { valueSatoshis: BigInt(HOLD_V), lockingBytecode: new Uint8Array(poolLocking), token: { category: hexToBytes(PUSD), amount: 100n } },
  { valueSatoshis: BigInt(FUND_V), lockingBytecode: new Uint8Array(w.lock) },
]
const preimage = generateSigningSerializationBCH({ inputIndex: 7, sourceOutputs, transaction: tx }, { coveredBytecode: w.lock, signingSerializationType: new Uint8Array([0x41]) })
const sig = bchSchnorrSign(hash256(preimage), w.priv)
const sig65 = new Uint8Array(65); sig65.set(sig); sig65[64] = 0x41
tx.inputs[7].unlockingBytecode = new Uint8Array([65, ...sig65, 33, ...w.pub33])

const hex = binToHex(encodeTransactionBCH(tx))
const decoded = decodeTransactionBCH(hexToBin(hex))
const inTot = 5 * STEP_V + POOL_V + HOLD_V + FUND_V
const outTot = POOL_V + 5 * STEP_V + HOLD_V + PAYOUT_V + Number(BigInt(FUND_V - 40000))
console.log("probe tx:", hex.length / 2, "B | in:", inTot, "| out:", outTot, "| fee:", inTot - outTot, `(${((inTot - outTot) / (hex.length / 2)).toFixed(3)} sat/B)`)

import { disassembleBytecode } from "@bitauth/libauth"
const NAMES = ["step exec0", "step exec1", "step exec2", "step genesis", "step terminal", "state covenant", "holdings covenant", "p2pkh funding"]
for (const [label, vmf] of [["consensus", false], ["standard", true]]) {
  const vm = createVirtualMachineBch2026(vmf)
  console.log(`── VM ${label} mode ──`)
  for (let i = 0; i < decoded.inputs.length; i++) {
    const st = vm.evaluate({ inputIndex: i, transaction: decoded, sourceOutputs })
    console.log("  input", i, "(" + NAMES[i] + ")", st.error ? "FAIL: " + st.error : "OK")
    if (st.error) {
      const trace = vm.debug({ inputIndex: i, transaction: decoded, sourceOutputs })
      const states = Array.isArray(trace) ? trace : trace.states || []
      const bad = states.filter(x => x.error).slice(0, 1)[0] || states[states.length - 1]
      console.log("    DEBUG failing ip:", bad.ip, "| error:", bad.error)
      if (i < 5) {
        const dis = disassembleBytecode(decoded.inputs[i].unlockingBytecode)
        const instrs = []
        for (const d of dis) { if (d.disassembly) instrs.push(d.disassembly); else for (const dd of (d.data ? [d] : d.sections || [])) instrs.push(dd.disassembly || (dd.data ? "DATA " + String.fromCharCode(...dd.data.slice(0, 8)) + "…" : "?")) }
        const ip = Number(bad.ip)
        for (let k = Math.max(0, ip - 14); k <= Math.min(instrs.length - 1, ip + 3); k++) console.log("      instr", k, k === ip ? ">>>" : "   ", String(instrs[k]).slice(0, 100))
      } else if (i === 5 || i === 6) {
        const asm = artifact.bytecode.split(" ")
        const ip = Number(bad.ip)
        for (let k = Math.max(0, ip - 8); k <= Math.min(asm.length - 1, ip + 2); k++) console.log("      asm", k, k === ip ? ">>>" : "   ", String(asm[k]).slice(0, 100))
      }
    }
  }
  break // consensus results are decisive for the logic questions; the live 11-20 ops already proved these unlockings standard-relay
}
console.log("DRY PROBE COMPLETE — nothing was broadcast")
