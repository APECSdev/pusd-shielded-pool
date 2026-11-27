// mn-unspents.mjs — list the unspents at the v4h pool lockings (prog/hLock/walks) to find
// any leftovers from the previous session's ab9 probes.
import tls from "node:tls"
import { createHash } from "node:crypto"
import { readFileSync } from "node:fs"
const s = JSON.parse(readFileSync("/home/apecs/cov/role2-pool4-state.mainnet-v4h.json", "utf8"))
const rpc = (m, p) => new Promise((res, rej) => { const x = tls.connect(50002, "bch.soul-dev.com", { timeout: 15000 }); let b = ""; x.on("secureConnect", () => x.write(JSON.stringify({ jsonrpc: "2.0", id: 1, method: m, params: p }) + "\n")); x.on("data", d => { b += d; const l = b.split("\n")[0]; if (l) { try { const o = JSON.parse(l); o.error ? rej(new Error(JSON.stringify(o.error).slice(0, 100))) : res(o.result); x.destroy() } catch {} } }); x.on("error", rej) })
for (const [name, lockingHex] of [["progLock", s.program.locking], ["hLock", s.program.hLockingHex], ["walkA", s.program.walkALockingHex], ["walkB", s.program.walkBLockingHex]]) {
  const sh = createHash("sha256").update(Buffer.from(lockingHex, "hex")).digest().reverse().toString("hex")
  const us = await rpc("blockchain.scripthash.listunspent", [sh, "include_tokens"])
  console.log(name, lockingHex.slice(0, 14) + "…:", us.length, "unspents:", us.map(u => u.tx_hash.slice(0, 10) + ":" + u.tx_pos + " " + u.value + "s" + (u.token_data ? " tok" + JSON.stringify(u.token_data.amount) + (u.token_data.nft?.commitment ? " com" + String(u.token_data.nft.commitment).length + "B" : "") : "")).join(" | ") || "NONE")
}
