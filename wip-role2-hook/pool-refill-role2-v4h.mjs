// pool-refill-role2-v4h.mjs — the V4H LOCK tx: the next action's TAGGED fuel pair + the
// walk-data dust pair + the H-covenant pair (the deposit slot in6, and — for the FIRST
// action only — the genesis holdings input in5).
//
// Outputs (beyond the v3 lock's fuel×2 + walks×2):
//   out4   in6, the deposit slot at H — the user's ASSET FT on a deposit (sign=0, pv>0),
//          tokenless dust otherwise;
//   out5   in5, the genesis holdings slot at H — tokenless dust, funded ONLY when the
//          pool has no holdings UTXO yet (the first action is the genesis DEPOSIT; every
//          later action takes in5 = the previous action's out2, never lock-funded);
//   then BCH change (+ ASSET FT change when the deposit UTXO splits).
// The fuel pair is NFT-ONLY in v4h (the deposit FT never rides the fuel — it rides in6).
//
// The H locking comes from the state file (program.hLockingHex). The ASSET FT selection
// reads state.assetCategory — the REAL PUSD at the wallet (the user's deposit), never
// minted by us.
//
// Usage (VM, from chunked/bn254/bn-native-sound/):
//   node pool-refill-role2-v4h.mjs --op /home/apecs/cov/role2-op4.json --network mainnet
//       [--state …] [--secrets …] [--fuel-per 23000] [--walk-per 2000] [--h-per 1000]
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import tls from 'node:tls';
import {
    binToHex, cashAddressToLockingBytecode, decodeTransaction, encodeDataPush,
    encodeTransactionBCH, generateSigningSerializationBCH, hash256, hexToBin,
    instantiateSecp256k1, instantiateSha256, SigningSerializationTypeBCH,
} from '@bitauth/libauth';

const argOf = (n, d) => { const i = process.argv.indexOf(n); return i >= 0 ? process.argv[i + 1] : d; };
const NETWORK = argOf('--network', 'chipnet');
if (NETWORK !== 'mainnet' && NETWORK !== 'chipnet') throw new Error('--network must be mainnet|chipnet');
const ELECTRUM_HOST = argOf('--electrum', NETWORK === 'mainnet' ? 'bch.soul-dev.com' : 'chipnet.bch.ninja');
const PREFIX = NETWORK === 'mainnet' ? 'bitcoincash:' : 'bchtest:';
const STATE = argOf('--state', NETWORK === 'mainnet' ? '/home/apecs/cov/role2-pool4-state.mainnet-v4h.json' : '/home/apecs/cov/role2-pool4-state.v4h.json');
const SECRETS = argOf('--secrets', NETWORK === 'mainnet' ? '/home/apecs/.secrets/mainnet-demo-cycle.json' : '/home/apecs/.secrets/wallet-a-role2-demo.json');
const OP = argOf('--op', '/home/apecs/cov/role2-op4.json');
const FUEL_PER = BigInt(argOf('--fuel-per', '23000'));
const WALK_PER = BigInt(argOf('--walk-per', '2000'));
const H_PER = BigInt(argOf('--h-per', '1000'));
const NO_WAIT = process.argv.includes('--no-wait');

const rpc = (method, params) => new Promise((res, rej) => {
    const sock = tls.connect(50002, ELECTRUM_HOST, { timeout: 15000 });
    let buf = '';
    sock.on('secureConnect', () => sock.write(JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }) + '\n'));
    sock.on('data', (d) => { buf += d.toString(); const line = buf.split('\n')[0];
        if (line) { try { const o = JSON.parse(line); if (o.error) rej(new Error(JSON.stringify(o.error))); else res(o.result); sock.destroy(); } catch { /* more */ } } });
    sock.on('error', rej);
    sock.on('timeout', () => { sock.destroy(); rej(new Error('electrum timeout: ' + method)); });
});

const state = JSON.parse(readFileSync(STATE, 'utf8'));
const op = JSON.parse(readFileSync(OP, 'utf8'));
const secrets = JSON.parse(readFileSync(SECRETS, 'utf8'));
const privateKey = hexToBin(String(secrets.privateKeyHex).replace(/^0x/, ''));
const address = secrets.addresses?.chipnet ?? secrets.address;
if (!address.startsWith(PREFIX)) throw new Error(`expected a ${NETWORK} address, got ` + address);
const sha256a = await instantiateSha256();
const secp = await instantiateSecp256k1();
const publicKey = secrets.publicKeyHex ? hexToBin(secrets.publicKeyHex) : secp.derivePublicKeyCompressed(privateKey);
if (typeof publicKey === 'string') throw new Error('pubkey derivation failed: ' + publicKey);
const fundLocking = cashAddressToLockingBytecode(address).bytecode;
const programLocking = hexToBin(state.program.locking);
const walkALocking = hexToBin(state.program.walkALockingHex);
const walkBLocking = hexToBin(state.program.walkBLockingHex);
const hLocking = hexToBin(state.program.hLockingHex);
if (!hLocking.length) throw new Error('state has no H locking — deployed by a pre-v4h tool?');
const CAT_BYTES = hexToBin(state.category);
const ASSET_BYTES = hexToBin(state.assetCategory);
const txidOf = (t) => binToHex(new Uint8Array(hash256(encodeTransactionBCH(t), sha256a)).reverse());
const P2PKH_SIGNED = 100;
const probeFee = (t) => BigInt(encodeTransactionBCH({ ...t, inputs: t.inputs.map((i) => ({ ...i, unlockingBytecode: new Uint8Array(P2PKH_SIGNED) })) }).length) * 2n;

/* ---- the deposit tag: SHA256 of the carrier's first 64 bytes — the action's own nullifiers ---- */
const c = op.covenant;
const nf0b = Buffer.from(c.nf0, 'hex'), nf1b = Buffer.from(c.nf1, 'hex');
assert.equal(nf0b.length + nf1b.length, 64, 'op covenant nullifier limbs must be 32+32 bytes');
const tag = createHash('sha256').update(Buffer.concat([nf0b, nf1b])).digest().toString('hex');
const pv = BigInt(c.publicValueAbs), sign = BigInt(c.isUnshield);
const IS_DEPOSIT = (sign === 0n && pv > 0n);
const GENESIS = !state.outpoints.holdings;   /* the first action: no holdings UTXO exists yet */
assert.ok(op.nullSet?.sibsA?.length === 254 && op.nullSet?.sibsB?.length === 254, 'the op file carries no v3 nullSet walk data — re-prove with role2-op-witness-v3.mjs');
console.log(`lock for ${op.action} pv=${pv} sign=${sign} · tag ${tag.slice(0, 16)}… · fuel ${FUEL_PER}×2 · walks ${WALK_PER}×2 · H pair ${H_PER}×2${IS_DEPOSIT ? ' · ASSET deposit ' + pv : ''}${GENESIS ? ' · GENESIS (in5 tokenless dust at H)' : ''}`);

/* ---- wallet UTXOs: 2 blanks + a plain BCH UTXO (+ the ASSET FT for a deposit) ---- */
const utxos = await rpc('blockchain.address.listunspent', [address, 'include_tokens']);
const blanks = utxos.filter((u) => u.token_data?.category === state.category && u.token_data.nft?.capability === 'mutable' && !u.token_data.nft.commitment);
if (blanks.length < 2) throw new Error(`only ${blanks.length} tag blank(s) at the wallet — run pool-tagbatch-role2.mjs through the guard`);
const plain = utxos.filter((u) => !u.token_data).sort((a, b) => b.value - a.value);
if (plain.length === 0) throw new Error('no plain wallet UTXO for the fuel sats');
let supply = null;
const NO_SLOT = process.argv.includes('--no-deposit-slot');
if (IS_DEPOSIT && !NO_SLOT) {
    const tokenUtxos = utxos.filter((u) => u.token_data?.category === state.assetCategory && !u.token_data.nft && BigInt(u.token_data.amount) >= pv);
    if (tokenUtxos.length === 0) throw new Error('no ASSET FT UTXO at the wallet for the requested deposit (the user must pre-send their PUSD here)');
    supply = tokenUtxos.sort((a, b) => Number(BigInt(b.token_data.amount) - BigInt(a.token_data.amount)))[0]; /* BigInt sort comparators throw — Number() (amounts are small) */
}

const nH = GENESIS ? 2n : 1n; /* in5 + in6 at genesis; only in6 after */
/* (with --no-deposit-slot the in6 output is omitted: fixed counts the FUNDED slots) */
const fixed = 2n * FUEL_PER + 2n * WALK_PER + ((GENESIS ? 2n : 1n) - ((IS_DEPOSIT && NO_SLOT) ? 1n : 0n)) * H_PER + (supply && BigInt(supply.token_data.amount) - pv > 0n ? 1000n : 0n);
const inSats = BigInt(plain[0].value) + BigInt(blanks[0].value) + BigInt(blanks[1].value) + (supply ? BigInt(supply.value) : 0n);
if (inSats < fixed + 2000n + 400n) throw new Error(`wallet UTXOs too small for the v4h lock: have ${inSats}, fixed ${fixed} + fees`);

const tx = {
    version: 2,
    locktime: 0,
    inputs: [
        { outpointTransactionHash: hexToBin(plain[0].tx_hash), outpointIndex: plain[0].tx_pos, sequenceNumber: 0xffffffff, unlockingBytecode: new Uint8Array(0) },
        { outpointTransactionHash: hexToBin(blanks[0].tx_hash), outpointIndex: blanks[0].tx_pos, sequenceNumber: 0xffffffff, unlockingBytecode: new Uint8Array(0) },
        { outpointTransactionHash: hexToBin(blanks[1].tx_hash), outpointIndex: blanks[1].tx_pos, sequenceNumber: 0xffffffff, unlockingBytecode: new Uint8Array(0) },
        ...(supply ? [{ outpointTransactionHash: hexToBin(supply.tx_hash), outpointIndex: supply.tx_pos, sequenceNumber: 0xffffffff, unlockingBytecode: new Uint8Array(0) }] : []),
    ],
    outputs: [
        /* out0/out1: the tagged fuel pair (NFT-ONLY in v4h — the deposit FT rides in6) */
        { lockingBytecode: programLocking, valueSatoshis: FUEL_PER, token: { category: CAT_BYTES, amount: 0n, nft: { capability: 'mutable', commitment: hexToBin(tag) } } },
        { lockingBytecode: programLocking, valueSatoshis: FUEL_PER, token: { category: CAT_BYTES, amount: 0n, nft: { capability: 'mutable', commitment: hexToBin(tag) } } },
        /* out2/out3: the walk-data pair */
        { lockingBytecode: new Uint8Array(walkALocking), valueSatoshis: WALK_PER },
        { lockingBytecode: new Uint8Array(walkBLocking), valueSatoshis: WALK_PER },
        /* out4: in6 — the deposit slot at H (the ASSET FT on a deposit; tokenless
           otherwise). With --no-deposit-slot the slot is PRE-FUNDED elsewhere (an
           H-locked deposit UTXO already on chain) and this lock omits it. */
        ...((IS_DEPOSIT && NO_SLOT) ? [] : [{ lockingBytecode: new Uint8Array(hLocking), valueSatoshis: H_PER, ...(IS_DEPOSIT ? { token: { category: ASSET_BYTES, amount: pv } } : {}) }]),
        /* BCH change */
        { lockingBytecode: fundLocking, valueSatoshis: 0n },
    ],
};
let changeIdx = (IS_DEPOSIT && NO_SLOT) ? 4 : 5;
if (GENESIS) {
    /* in5 — the genesis holdings slot at H, tokenless dust (the first action's
       DEPOSIT rides in6; in5 becomes the holdings line the action recreates at out2).
       The change sits BELOW it: pushing in5 shifts the change's index by one. */
    tx.outputs.push({ lockingBytecode: new Uint8Array(hLocking), valueSatoshis: H_PER });
    /* the change sits BELOW in5 (the literal holds it before this push): its index
       DOES NOT MOVE — incrementing it pointed the value-assignment at in5, leaving
       the change at 0n = dust (the 2026-11-27 mainnet "dust (code 64)" chase). */
}
if (supply && BigInt(supply.token_data.amount) - pv > 0n) tx.outputs.push({ lockingBytecode: fundLocking, valueSatoshis: 1000n, token: { category: ASSET_BYTES, amount: BigInt(supply.token_data.amount) - pv } }); /* a zero-amount FT change output would be invalid — skip if nothing remains */
tx.outputs[changeIdx].valueSatoshis = inSats - fixed - probeFee(tx);

const sources = [
    { lockingBytecode: fundLocking, valueSatoshis: BigInt(plain[0].value) },
    ...[blanks[0], blanks[1]].map((b) => ({ lockingBytecode: fundLocking, valueSatoshis: BigInt(b.value), token: { category: CAT_BYTES, amount: 0n, nft: { capability: 'mutable', commitment: new Uint8Array(0) } } })),
    ...(supply ? [{ lockingBytecode: fundLocking, valueSatoshis: BigInt(supply.value), token: { category: ASSET_BYTES, amount: BigInt(supply.token_data.amount) } }] : []),
];
for (let i = 0; i < tx.inputs.length; i += 1) {
    const serialization = generateSigningSerializationBCH(
        { inputIndex: i, sourceOutputs: sources, transaction: tx },
        { coveredBytecode: fundLocking, signingSerializationType: Uint8Array.of(SigningSerializationTypeBCH.allOutputs) },
        sha256a,
    );
    const digest = hash256(serialization, sha256a);
    const signature = secp.signMessageHashSchnorr(privateKey, digest);
    if (typeof signature === 'string') throw new Error('Schnorr signing failed: ' + signature);
    tx.inputs[i].unlockingBytecode = Uint8Array.from([...encodeDataPush(Uint8Array.from([...signature, SigningSerializationTypeBCH.allOutputs])), ...encodeDataPush(publicKey)]);
}
const hex = binToHex(encodeTransactionBCH(tx));
const decoded = decodeTransaction(hexToBin(hex));
if (typeof decoded === 'string') throw new Error('lock does not decode: ' + decoded);
const txid = txidOf(tx);
console.log(`lock tx ${txid} · ${hex.length / 2}B · fuel ${FUEL_PER}×2 + walks ${WALK_PER}×2 + H pair${IS_DEPOSIT ? ` (in6 carries the ${pv} ASSET deposit)` : ''}`);

if (process.argv.includes('--dump')) {
    for (const [i, o] of tx.outputs.entries()) console.log(`out${i}: ${o.valueSatoshis} sats${o.token ? " token cat=" + Buffer.from(o.token.category).toString("hex").slice(0, 10) + " amt=" + o.token.amount + (o.token.nft ? " NFT" : "") : ""} lockingLen=${o.lockingBytecode.length}`);
    console.log('inputs:', tx.inputs.map((i) => i.outpointIndex).join(","));
    console.log('HEX:', hex.slice(0, 120) + "…");
    process.exit(0);
}
console.log('broadcasting…');
console.log('RESULT: ' + await rpc('blockchain.transaction.broadcast', [hex]));
state.outpoints.actionInputs = [
    { txid, vout: 0, sats: Number(FUEL_PER), tag },
    { txid, vout: 1, sats: Number(FUEL_PER), tag },
    { txid, vout: 2, sats: Number(WALK_PER), walk: 'A' },
    { txid, vout: 3, sats: Number(WALK_PER), walk: 'B' },
    ...((IS_DEPOSIT && NO_SLOT) ? [] : [{ txid, vout: 4, sats: Number(H_PER), slot: 'in6', ...(IS_DEPOSIT ? { ftAmount: pv.toString() } : {}) }]),
    ...(GENESIS ? [{ txid, vout: (IS_DEPOSIT && NO_SLOT) ? 5 : 6, sats: Number(H_PER), slot: 'in5' }] : []),
];
writeFileSync(STATE, JSON.stringify(state, null, 2) + '\n');
console.log('state updated: actionInputs = 2 fuel + 2 walks + in6' + (GENESIS ? ' + in5 (genesis)' : '') + ' of ' + txid.slice(0, 16) + '…');

if (NO_WAIT) { console.log('--no-wait — broadcast the action now (pool-op-role2-v4h.mjs); it may spend the lock unconfirmed (atomic lock+act).'); process.exit(0); }
let confirmed = false;
for (let i = 0; i < 60; i += 1) {
    await new Promise((r) => setTimeout(r, 30000));
    try { await rpc('blockchain.transaction.get_merkle', [txid]); confirmed = true; break; } catch { }
    process.stdout.write('.');
}
console.log('');
if (!confirmed) throw new Error('lock unconfirmed after 30 min — the fuel is tagged for THIS op; either keep waiting, re-prove with the same notes (same nullifiers, tag stays valid), or abandon the fuel');
console.log('lock confirmed.');
process.exit(0);
