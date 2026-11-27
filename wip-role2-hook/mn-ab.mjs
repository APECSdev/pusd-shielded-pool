// mn-ab.mjs — the lean mainnet OUTTOKCOMMIT/UTXOTOKCOMMIT measurement ladder (the §5.1 mission).
// Modes:
//   size <n>     — the test P2SH32 asserts SIZE(OUTTOKCOMMIT(1)) == n on a 96-B-commitment NFT at output 1
//   digest       — the test asserts OUTTOKCOMMIT(1) == hash256(the 96-B commitment) (the digest hypothesis)
//   utxosize <n> — the test P2SH32 ITSELF carries the 96-B NFT and asserts SIZE(UTXOTOKCOMMIT(0)) == n
// Each probe = t1 (fund the test + carry the NFT at P2PKH) + t2 (spend the test — the verdict = t2 relays or not).
// The NFT (a blank on the first probe) is RECYCLED through the ladder via t2's output 1 — one blank total.
import tls from "node:tls";
import { readFileSync } from "node:fs";
import { binToHex, cashAddressToLockingBytecode, encodeTransactionBCH, generateSigningSerializationBCH, hash256, hexToBin, instantiateSecp256k1, instantiateSha256, SigningSerializationTypeBCH, encodeDataPush, createVirtualMachineBch2026 } from "@bitauth/libauth";
import { p2sh32 } from "./vm.mjs";
import { Asm, OP, pushData } from "./asm.mjs";

const MODE = process.argv[2] ?? "size";
const N = Number(process.argv[3] ?? 96);
const state = JSON.parse(readFileSync("/home/apecs/cov/role2-pool4-state.mainnet-v4h.json", "utf8"));
const op = JSON.parse(readFileSync("/home/apecs/cov/role2-op4-mn-dep.json", "utf8"));
const secrets = JSON.parse(readFileSync("/home/apecs/.secrets/mainnet-demo-cycle.json", "utf8"));
const rpc = (m, p) => new Promise((res, rej) => { const s = tls.connect(50002, "bch.soul-dev.com", { timeout: 15000 }); let b = ""; s.on("secureConnect", () => s.write(JSON.stringify({ jsonrpc: "2.0", id: 1, method: m, params: p }) + "\n")); s.on("data", (d) => { b += d; const l = b.split("\n")[0]; if (l) { try { const o = JSON.parse(l); o.error ? rej(new Error((o.error.message ?? "").split("\n").filter((x) => x.trim()).pop().slice(0, 140))) : res(o.result); s.destroy(); } catch {} } }); s.on("error", rej); });
const sha256a = await instantiateSha256(); const secp = await instantiateSecp256k1();
const pk = hexToBin(String(secrets.privateKeyHex).replace(/^0x/, ""));
const pub = secp.derivePublicKeyCompressed(pk);
const fundLocking = cashAddressToLockingBytecode(secrets.address).bytecode;
const CAT = hexToBin(state.category);

// the REAL 96-B commitment the node rejected (the deposit op's): root ‖ finalNullRoot ‖ balance
const be32 = (v) => { const b = Buffer.alloc(32); let x = BigInt(v); for (let i = 31; i >= 0 && x > 0n; i--) { b[i] = Number(x & 0xffn); x >>= 8n; } return b; };
const commit96 = Buffer.concat([Buffer.from(be32(BigInt(op.newRoot))).reverse(), Buffer.from(op.nullSet.finalNullRoot, "hex"), Buffer.from(be32(100n)).reverse()]);
if (commit96.length !== 96) throw new Error("commit96 must be 96 B, got " + commit96.length);
console.log(`mode=${MODE} n=${N} | commit96: ${commit96.toString("hex").slice(0, 24)}… (${commit96.length} B)`);

const IX = { TXVERSION: 0xc2, UTXOTOKCOMMIT: 0xcf, OUTTOKCOMMIT: 0xd2 };
const a = new Asm([]);
a.op(IX.TXVERSION, 0, "tv").push(2).op(OP.NUMEQUALVERIFY, 2);
if (MODE === "size") {
  a.push(1).op(IX.OUTTOKCOMMIT, 1, "o1c");
  a.op(OP.SIZE, 1, "o1c", "sz").push(N).op(OP.NUMEQUALVERIFY, 2);
} else if (MODE === "digest") {
  a.push(1).op(IX.OUTTOKCOMMIT, 1, "o1c");
  a.pushBytes([...hash256(commit96, sha256a)]).op(OP.EQUALVERIFY, 2);
} else if (MODE === "utxosize") {
  a.push(0).op(IX.UTXOTOKCOMMIT, 1, "u0c");
  a.op(OP.SIZE, 1, "u0c", "sz").push(N).op(OP.NUMEQUALVERIFY, 2);
} else throw new Error("mode?");
while (a.st.length > 0) a.drop(a.st[a.st.length - 1]);
a.push(1);
const test = Uint8Array.from(a.code);
const testLocking = p2sh32(test);
console.log("test script:", test.length, "B | locking: aa20" + binToHex(hash256(test, sha256a)).slice(0, 24) + "…87");

const signP2pkh = async (tx, sources, i) => { const ser = generateSigningSerializationBCH({ inputIndex: i, sourceOutputs: sources, transaction: tx }, { coveredBytecode: fundLocking, signingSerializationType: Uint8Array.of(SigningSerializationTypeBCH.allOutputs) }, sha256a); const sig = secp.signMessageHashSchnorr(pk, hash256(ser, sha256a)); tx.inputs[i].unlockingBytecode = Uint8Array.from([...encodeDataPush(Uint8Array.from([...sig, SigningSerializationTypeBCH.allOutputs])), ...encodeDataPush(pub)]); };
const txidOf = (t) => binToHex(new Uint8Array(hash256(encodeTransactionBCH(t), sha256a)).reverse());
const sizeOf = (t) => encodeTransactionBCH({ ...t, inputs: t.inputs.map((i) => ({ ...i, unlockingBytecode: new Uint8Array(150) })) }).length;
const FEE_RATE = 2n; // sat/B — the session's probe convention

// the wallet inventory
const utxos = await rpc("blockchain.address.listunspent", [secrets.address, "include_tokens"]);
const tok = (u) => u.token_data;
const plainAll = utxos.filter((u) => !tok(u)).sort((x, y) => y.value - x.value);
const blanks = utxos.filter((u) => tok(u)?.category === state.category && tok(u).nft?.capability === "mutable" && !tok(u).nft.commitment);
const recycled = utxos.filter((u) => tok(u)?.category === state.category && tok(u).nft?.capability === "mutable" && tok(u).nft.commitment && Buffer.from(tok(u).nft.commitment, "hex").equals(commit96));
const fts = utxos.filter((u) => tok(u)?.category === state.category && !tok(u).nft).sort((x, y) => BigInt(y.token_data.amount) - BigInt(x.token_data.amount));
console.log(`wallet: plain ${plainAll.map(u => u.value).join("+")} = ${plainAll.reduce((s, u) => s + u.value, 0)} | blanks ${blanks.length} | recycled-96B-NFT ${recycled.length} | FT utxos ${fts.length}`);
if (!fts.length) throw new Error("no pool-cat FT");

// the NFT source: a recycled 96-B NFT from a previous probe, else a blank
const nftSrc = recycled[0] ?? blanks[0];
if (!nftSrc) throw new Error("no NFT source (no blank, no recycled probe NFT)");
const ftSrc = fts[0];
const plains = plainAll.filter((u) => u.value >= 546).slice(0, 4);
const plainSum = plains.reduce((s, u) => s + BigInt(u.value), 0n);
console.log(`NFT source: ${nftSrc.tx_hash.slice(0, 12)}:${nftSrc.tx_pos} (${recycled[0] ? "recycled 96-B" : "blank"}) | FT: ${ftSrc.tx_hash.slice(0, 12)}:${ftSrc.tx_pos} = ${ftSrc.token_data.amount}`);

// ── t1: fund the test; the NFT rides at P2PKH ──
const t1In = [...plains.map((u) => ({ outpointTransactionHash: hexToBin(u.tx_hash), outpointIndex: u.tx_pos, sequenceNumber: 0xffffffff, unlockingBytecode: new Uint8Array(0) })),
  { outpointTransactionHash: hexToBin(nftSrc.tx_hash), outpointIndex: nftSrc.tx_pos, sequenceNumber: 0xffffffff, unlockingBytecode: new Uint8Array(0) },
  { outpointTransactionHash: hexToBin(ftSrc.tx_hash), outpointIndex: ftSrc.tx_pos, sequenceNumber: 0xffffffff, unlockingBytecode: new Uint8Array(0) }];
const t1Fixed = 3000n + 1000n + 1000n;
const fee1 = BigInt(sizeOf({ version: 2, locktime: 0, inputs: t1In, outputs: [] })) * FEE_RATE;
const t1Change = plainSum + BigInt(nftSrc.value) + BigInt(ftSrc.value) - t1Fixed - fee1;
if (t1Change < 546n) throw new Error("t1 change too small: " + t1Change);
const t1 = { version: 2, locktime: 0, inputs: t1In, outputs: [
  ...(MODE === "utxosize"
    ? [{ lockingBytecode: testLocking, valueSatoshis: 3000n, token: { category: CAT, amount: 0n, nft: { capability: "mutable", commitment: Uint8Array.from(commit96) } } }]
    : [{ lockingBytecode: testLocking, valueSatoshis: 3000n }]),
  ...(MODE === "utxosize"
    ? [{ lockingBytecode: fundLocking, valueSatoshis: 1000n, token: { category: CAT, amount: BigInt(ftSrc.token_data.amount) } }, { lockingBytecode: fundLocking, valueSatoshis: t1Change }]
    : [{ lockingBytecode: fundLocking, valueSatoshis: 1000n, token: { category: CAT, amount: 0n, nft: { capability: "mutable", commitment: Uint8Array.from(commit96) } } },
       { lockingBytecode: fundLocking, valueSatoshis: 1000n, token: { category: CAT, amount: BigInt(ftSrc.token_data.amount) } },
       { lockingBytecode: fundLocking, valueSatoshis: t1Change }]),
]};
const t1src = [...plains.map((u) => ({ lockingBytecode: fundLocking, valueSatoshis: BigInt(u.value) })),
  { lockingBytecode: fundLocking, valueSatoshis: BigInt(nftSrc.value), token: tok(nftSrc) ? { category: CAT, amount: 0n, nft: { capability: "mutable", commitment: tok(nftSrc).nft?.commitment ? Uint8Array.from(Buffer.from(tok(nftSrc).nft.commitment, "hex")) : Uint8Array.from(new Uint8Array(0)) } } : undefined },
  { lockingBytecode: fundLocking, valueSatoshis: BigInt(ftSrc.value), token: { category: CAT, amount: BigInt(ftSrc.token_data.amount) } }];
for (let i = 0; i < t1.inputs.length; i++) await signP2pkh(t1, t1src, i);
const t1hex = binToHex(encodeTransactionBCH(t1));
const t1id = txidOf(t1);
await rpc("blockchain.transaction.broadcast", [t1hex]);
console.log("t1 RELAYED:", t1id, "|", t1hex.length / 2, "B | fee", fee1, "| change", t1Change);

// ── t2: spend the test — THE VERDICT ──
const t2In = MODE === "utxosize"
  ? [{ outpointTransactionHash: hexToBin(t1id), outpointIndex: 0, sequenceNumber: 0xfffffffe, unlockingBytecode: Uint8Array.from(pushData(test)) },
     { outpointTransactionHash: hexToBin(t1id), outpointIndex: 1, sequenceNumber: 0xfffffffe, unlockingBytecode: new Uint8Array(0) },
     { outpointTransactionHash: hexToBin(t1id), outpointIndex: 2, sequenceNumber: 0xfffffffe, unlockingBytecode: new Uint8Array(0) }]
  : [{ outpointTransactionHash: hexToBin(t1id), outpointIndex: 0, sequenceNumber: 0xfffffffe, unlockingBytecode: Uint8Array.from(pushData(test)) },
     { outpointTransactionHash: hexToBin(t1id), outpointIndex: 1, sequenceNumber: 0xfffffffe, unlockingBytecode: new Uint8Array(0) },
     { outpointTransactionHash: hexToBin(t1id), outpointIndex: 2, sequenceNumber: 0xfffffffe, unlockingBytecode: new Uint8Array(0) },
     { outpointTransactionHash: hexToBin(t1id), outpointIndex: 3, sequenceNumber: 0xfffffffe, unlockingBytecode: new Uint8Array(0) }];
const t2InVals = MODE === "utxosize" ? [3000n, 1000n, t1Change] : [3000n, 1000n, 1000n, t1Change];
const fee2 = BigInt(sizeOf({ version: 2, locktime: 0, inputs: t2In, outputs: [] })) * FEE_RATE;
const t2Change = t2InVals.reduce((s, v) => s + v, 0n) - 2000n - fee2;
if (t2Change < 546n) throw new Error("t2 change too small: " + t2Change);
// output 1 MUST carry the 96-B NFT for modes size/digest (the probe reads OUTTOKCOMMIT(1));
// for utxosize the NFT is the test INPUT's token — recycle it to output 0.
const t2 = { version: 2, locktime: 0, inputs: t2In, outputs: MODE === "utxosize"
  ? [{ lockingBytecode: fundLocking, valueSatoshis: 1000n, token: { category: CAT, amount: 0n, nft: { capability: "mutable", commitment: Uint8Array.from(commit96) } } },
     { lockingBytecode: fundLocking, valueSatoshis: 1000n, token: { category: CAT, amount: BigInt(ftSrc.token_data.amount) } },
     { lockingBytecode: fundLocking, valueSatoshis: t2Change }]
  : [{ lockingBytecode: fundLocking, valueSatoshis: 1000n, token: { category: CAT, amount: BigInt(ftSrc.token_data.amount) } },
     { lockingBytecode: fundLocking, valueSatoshis: 1000n, token: { category: CAT, amount: 0n, nft: { capability: "mutable", commitment: Uint8Array.from(commit96) } } },
     { lockingBytecode: fundLocking, valueSatoshis: t2Change }] };
const t2src = MODE === "utxosize"
  ? [{ lockingBytecode: testLocking, valueSatoshis: 3000n, token: { category: CAT, amount: 0n, nft: { capability: "mutable", commitment: Uint8Array.from(commit96) } } },
     { lockingBytecode: fundLocking, valueSatoshis: 1000n, token: { category: CAT, amount: BigInt(ftSrc.token_data.amount) } },
     { lockingBytecode: fundLocking, valueSatoshis: t1Change }]
  : [{ lockingBytecode: testLocking, valueSatoshis: 3000n },
     { lockingBytecode: fundLocking, valueSatoshis: 1000n, token: { category: CAT, amount: 0n, nft: { capability: "mutable", commitment: Uint8Array.from(commit96) } } },
     { lockingBytecode: fundLocking, valueSatoshis: 1000n, token: { category: CAT, amount: BigInt(ftSrc.token_data.amount) } },
     { lockingBytecode: fundLocking, valueSatoshis: t1Change }];
for (let i = (MODE === "utxosize" ? 1 : 1); i < t2.inputs.length; i++) await signP2pkh(t2, t2src, i);

// local VM rehearsal of the test input (both modes) before broadcasting
const t2hex = binToHex(encodeTransactionBCH(t2));
const { decodeTransactionBCH } = await import("@bitauth/libauth");
const decoded = decodeTransactionBCH(hexToBin(t2hex));
for (const [label, vm] of [["consensus", createVirtualMachineBch2026(false)], ["standard", createVirtualMachineBch2026(true)]]) {
  const st = vm.evaluate({ inputIndex: 0, transaction: decoded, sourceOutputs: t2src });
  console.log(`  local VM ${label} test input:`, st.error ? "REJECT (" + String(st.error).slice(0, 60) + ")" : "ACCEPT");
}
console.log("t2:", t2hex.length / 2, "B | fee", fee2, "| change", t2Change);
try { await rpc("blockchain.transaction.broadcast", [t2hex]); console.log(`>>> ${MODE} ${N}: RELAYED (PASS)`); } catch (e) { console.log(`>>> ${MODE} ${N}: ${String(e.message ?? e).slice(0, 140)}`); }
