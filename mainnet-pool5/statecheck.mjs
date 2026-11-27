// ~/matrix/statecheck.mjs — the pre-op state verification for the Path-A UNSHIELD+SHIELD
// 1) rebuild the seed tree + current tree + nf/cm/actionHash from gen-demo-vector.mjs's
//    recorded secrets; byte-compare against op-meta.json (which the LIVE TRANSFER used)
// 2) live wallet balance on mainnet (BCH + PUSD + pool-cat)
// 3) inspect the user's 5-unit UTXO (f4b245097a06bd:0) and the live pool UTXOs
import { readFileSync } from "node:fs"
import { createHash } from "node:crypto"
import { connect } from "./wallet.mjs"
import { buildPoseidon } from "/home/apecs/zkb/pusd-shielded-pool/node_modules/circomlibjs/main.js"

const HOME = process.env.HOME
const poseidon = await buildPoseidon()
const F = poseidon.F
const H = (...xs) => F.toObject(poseidon(xs))
const commit = (v, o, rho, r) => H(v, o, rho, r), nullifier = (nk, rho) => H(nk, rho)
const zeros = [0n]; for (let d = 1; d <= 20; d++) zeros.push(H(zeros[d - 1], zeros[d - 1]))
const be32 = (bi) => { const b = Buffer.alloc(32, 0); let x = BigInt(bi); for (let i = 31; i >= 0 && x > 0n; i--) { b[i] = Number(x & 0xffn); x >>= 8n } return b }
const le32 = (bi) => Buffer.from(be32(bi).reverse())
function merklePath(leaves, index) {
  const pe = [], pb = []; let idx = index, cur = new Map(leaves.map((v, i) => [i, v]))
  for (let d = 0; d < 20; d++) {
    const s = idx % 2 === 0 ? idx + 1 : idx - 1; pe.push(cur.get(s) ?? zeros[d]); pb.push(idx % 2)
    const nx = new Map(), ks = new Set([...cur.keys()].map(k => k >> 1)); ks.add(idx >> 1)
    for (const k of ks) { nx.set(k, H(cur.get(2 * k) ?? zeros[d], cur.get(2 * k + 1) ?? zeros[d])) } cur = nx; idx >>= 1
  }
  return { pathElements: pe, pathBits: pb, root: cur.get(0) ?? zeros[20] }
}
function actionHashSHA256(nf0, nf1, cm0, cm1, pvAbs, pvSign, category, newRoot) {
  const preimage = Buffer.concat([be32(nf0), be32(nf1), be32(cm0), be32(cm1), be32(pvAbs), be32(pvSign), be32(category), be32(newRoot)])
  const h = createHash("sha256").update(preimage).digest()
  h[0] &= 0x1f
  return BigInt("0x" + h.toString("hex"))
}

// ── the recorded secrets (gen-demo-vector.mjs, verbatim) ──
const ownerPub = 111n, nk0 = 222n, nk1 = 333n
const in0 = { value: 60n, ownerPub, rho: 1001n, r: 5001n }, in1 = { value: 40n, ownerPub, rho: 1002n, r: 5002n }
const c0 = commit(in0.value, ownerPub, in0.rho, in0.r), c1 = commit(in1.value, ownerPub, in1.rho, in1.r)
const out0 = { value: 70n, ownerPub: 444n, rho: 2001n, r: 6001n }, out1 = { value: 30n, ownerPub: 555n, rho: 2002n, r: 6002n }
const cm0 = commit(out0.value, out0.ownerPub, out0.rho, out0.r), cm1 = commit(out1.value, out1.ownerPub, out1.rho, out1.r)
const nf0 = nullifier(nk0, in0.rho), nf1 = nullifier(nk1, in1.rho)
const assetCategory = 0x2469acc5afa4b10cb5b5c04afb89c3a3ffd61c5da9c01e26d00951cae2a02544n
const seedRoot = merklePath([c0, c1], 0).root
const curRoot = merklePath([c0, c1, cm0, cm1], 0).root
const curAction = actionHashSHA256(nf0, nf1, cm0, cm1, 0n, 0n, assetCategory, curRoot)

const meta = JSON.parse(readFileSync(HOME + "/zkb/tools/op-meta.json", "utf8"))
const eq = (name, hexLE, bi) => { const ok = Buffer.from(hexLE, "hex").equals(le32(bi)); console.log(`  ${name}: ${ok ? "MATCH" : "MISMATCH"}  (op-meta ${hexLE.slice(0, 16)}…)`); return ok }
console.log("── tree/secret reconstruction vs op-meta.json (the LIVE TRANSFER's own args) ──")
let all = true
all &= eq("seedRoot (49bda9bd)", meta.merkleRoot, seedRoot)
all &= eq("nf0", meta.nf0, nf0)
all &= eq("nf1", meta.nf1, nf1)
all &= eq("cm0 (current 70-unit note)", meta.cm0, cm0)
all &= eq("cm1 (current 30-unit note)", meta.cm1, cm1)
all &= eq("curRoot (d5ec91ad)", meta.newMerkleRoot, curRoot)
all &= eq("actionHash", meta.actionHash, curAction)
console.log(all ? "ALL MATCH — the current notes ARE the recorded demo secrets; NOTHING is missing" : "MISMATCH — do not proceed")

// ── live wallet state ──
const w = JSON.parse(readFileSync(HOME + "/secrets/mainnet-demo-cycle.json", "utf8"))
import { sha256 } from "@noble/hashes/sha2.js"
import { p2pkhScript } from "./txbuild.ts"
import { decodeCashAddress } from "./cashaddr.ts"
import { hexToBytes } from "./identity.ts"
const lock = p2pkhScript(decodeCashAddress(w.address).hash)
const sh = Buffer.from(sha256(lock)).reverse().toString("hex")
const e = await connect()
const us = await e.call("blockchain.scripthash.listunspent", [sh, "include_tokens"])
const tok = u => u.token_data || u.token
const bch = us.filter(u => !tok(u)).sort((a, b) => b.value - a.value)
const pusd = us.filter(u => tok(u)?.category === "2469acc5afa4b10cb5b5c04afb89c3a3ffd61c5da9c01e26d00951cae2a02544")
console.log("\n── live wallet (mainnet, cashnode.bch.ninja) ──")
console.log("  BCH plain:", bch.map(u => `${u.tx_hash.slice(0, 12)}:${u.tx_pos}=${u.value}`).join("  ") || "NONE", "| total:", bch.reduce((s, u) => s + u.value, 0))
console.log("  PUSD:", pusd.map(u => `${u.tx_hash.slice(0, 12)}:${u.tx_pos}=${tok(u).amount} FT / ${u.value} sats`).join("  ") || "NONE", "| total FT:", pusd.reduce((s, u) => s + BigInt(tok(u).amount), 0n))
console.log("  other tokens:", us.filter(u => tok(u) && tok(u).category !== "2469acc5afa4b10cb5b5c04afb89c3a3ffd61c5da9c01e26d00951cae2a02544").length)

// ── the user's 5-unit UTXO + the live pool state ──
const probeTx = async (txid, vouts) => {
  try {
    const t = await e.call("blockchain.transaction.get", [txid, true])
    for (const v of vouts) {
      const o = t.vout[v]
      console.log(`  ${txid.slice(0, 16)}…:${v} = ${o.value} sats, ${o.tokenData ? `token ${o.tokenData.category.slice(0, 16)}… amt ${JSON.stringify(o.tokenData.amount)} commit ${o.tokenData.commitment ? o.tokenData.commitment.slice(0, 16) + "…" : "none"}` : "no token"}`)
    }
    return t
  } catch (err) { console.log(`  ${txid.slice(0, 16)}…: ERROR ${err.message.slice(0, 100)}`); return null }
}
console.log("\n── the user's 5-unit UTXO (f4b245097a06bd…) ──")
const hist = await e.call("blockchain.scripthash.get_history", [sh])
const u5 = hist.find(h => h.tx_hash.startsWith("f4b245097a06bd"))
if (u5) { console.log("  full txid:", u5.tx_hash, "height", u5.height); await probeTx(u5.tx_hash, [0]) } else console.log("  NOT in wallet history")

console.log("\n── the live pool (poolLocking scripthash) ──")
const pool = JSON.parse(readFileSync(HOME + "/matrix/pool4.json", "utf8"))
const psh = Buffer.from(sha256(Buffer.from(pool.poolLocking, "hex"))).reverse().toString("hex")
const ph = await e.call("blockchain.scripthash.get_history", [psh])
const transfer = ph.find(h => h.tx_hash.startsWith("4fda8a8b"))
console.log("  pool scripthash history:", ph.length, "txs | the TRANSFER:", transfer ? transfer.tx_hash + " (h " + transfer.height + ")" : "NOT FOUND")
if (transfer) await probeTx(transfer.tx_hash, [0, 1, 4, 5, 6])
const pusdUnspent = await e.call("blockchain.scripthash.listunspent", [psh, "include_tokens"])
console.log("  pool unspents:", pusdUnspent.map(u => `${u.tx_hash.slice(0, 12)}:${u.tx_pos}${(u.token_data || u.token) ? " tok " + JSON.stringify((u.token_data || u.token).amount) : " " + u.value + "s"}`).join(" | "))
e.close()
