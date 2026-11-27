// merge-mpc-sweep.mjs — merge the 4 post-MPC sweep shards into pool-sweep-v3-mpc-report.json
// (the pool-sweep-v3-report.json precedent: one JSON with {shape, shards, results}).
import { readFileSync, writeFileSync } from "node:fs"

const shards = [0, 1, 2, 3].map(k => JSON.parse(readFileSync(`/tmp/pool-sweep-v3mpc-s${k}.json`, "utf8")))
const results = shards.flatMap(s => s.results)
const failed = results.filter(r => r.error || r.failed || r.reject === false)
const report = {
  shape: shards[0].shape,
  shards: shards.map(s => ({ shard: s.shard, cases: s.results.length, inputs: s.inputs })),
  results,
}
writeFileSync("/home/apecs/cov/pool-sweep-v3-mpc-report.json", JSON.stringify(report, null, 1))
console.log("merged:", results.length, "results | failed:", failed.length, "| shape:", report.shape)
const noVm = results.filter(r => !r.consensus || !r.standard)
console.log("cases missing VM verdicts:", noVm.length)
if (failed.length || noVm.length || results.length !== 69) { console.log("GATE FAILED"); process.exit(1) }
console.log("GATE PASSED — 69 cases, 0 failed")
