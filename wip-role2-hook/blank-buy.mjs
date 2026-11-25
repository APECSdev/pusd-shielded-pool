// blank-buy.mjs — the BUYER-side self-service acquisition: take a blank out of the vending
// covenant (blank-vending.mjs) using ONLY the buyer's own key. There is NO operator
// signature in this transaction — input 0 satisfies the covenant (pay the exact pinned
// price, the blank follows the money), input 1 is the buyer's own P2PKH sats. This tool
// is the proof that acquisition is PERMISSIONLESS: run it with a key the operator has
// never seen and watch it confirm.
//
// The covenant pins EVERYTHING the buyer may not choose: the price, the payment
// destination, the blank's shape (category + mutable + EMPTY commitment + 0 FT), the
// float, and delivery to the funding input's own locking. The buyer chooses only where
// their change goes — and pays the fee.
//
// Usage (VM, from chunked/bn254/bn-native-sound/):
//   node blank-buy.mjs --key /home/apecs/cov/stranger-demo-key.json
//        [--state …] [--vending-utxo <txid:vout>] [--dry]
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import tls from 'node:tls';
import {
    binToHex, cashAddressToLockingBytecode, decodeTransaction, encodeCashAddress,
    encodeDataPush, encodeTransactionBCH, generateSigningSerializationBCH, hash160, hash256,
    hexToBin, instantiateRipemd160, instantiateSecp256k1, instantiateSha256,
    SigningSerializationTypeBCH,
} from '@bitauth/libauth';
import { VMS } from './vm.mjs';
import { vendingRedeem, vendingLockingOf } from './blank-vending.mjs';

const argOf = (n, d) => { const i = process.argv.indexOf(n); return i >= 0 ? process.argv[i + 1] : d; };
const STATE = argOf('--state', '/home/apecs/cov/role2-pool-state.json');
const KEYFILE = argOf('--key', null);
const PICK = argOf('--vending-utxo', null);
const DRY = process.argv.includes('--dry');
if (!KEYFILE) throw new Error('--key <file> is required — whose key buys is the whole point');

/* electrum raw TLS JSON-RPC; chipnet.bch.ninja:50002 — Fulcrum 2.1.3, live-verified */
const rpc = (method, params) => new Promise((res, rej) => {
    const sock = tls.connect(50002, 'chipnet.bch.ninja', { timeout: 15000 });
    let buf = '';
    sock.on('secureConnect', () => sock.write(JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }) + '\n'));
    sock.on('data', (d) => { buf += d.toString(); const line = buf.split('\n')[0];
        if (line) { try { const o = JSON.parse(line); if (o.error) rej(new Error(JSON.stringify(o.error))); else res(o.result); sock.destroy(); } catch { /* more */ } } });
    sock.on('error', rej);
    sock.on('timeout', () => { sock.destroy(); rej(new Error('electrum timeout: ' + method)); });
});

const state = JSON.parse(readFileSync(STATE, 'utf8'));
const key = JSON.parse(readFileSync(KEYFILE, 'utf8'));
const privateKey = hexToBin(String(key.privateKeyHex).replace(/^0x/, ''));
const sha256a = await instantiateSha256();
const ripemd = await instantiateRipemd160();
const secp = await instantiateSecp256k1();
const publicKey = secp.derivePublicKeyCompressed(privateKey);
if (typeof publicKey === 'string') throw new Error('pubkey derivation failed: ' + publicKey);
const enc = encodeCashAddress({ prefix: 'bchtest', type: 'p2pkh', payload: hash160(publicKey, { ripemd160: ripemd, sha256: sha256a }) });
const buyerAddress = typeof enc === 'string' ? enc : enc.address;   /* both return forms exist */
if (typeof buyerAddress !== 'string') throw new Error('address encode failed: ' + JSON.stringify(enc));
const buyerLocking = cashAddressToLockingBytecode(buyerAddress).bytecode;
console.log(`buyer: ${buyerAddress} — an unknown key to the operator; this is the permissionless test`);

/* rebuild the vending covenant from PUBLISHED parameters and pin it against the recorded
   locking — a buyer never trusts a locking they cannot reproduce (source-drift refusal) */
if (!state.vending?.operatorAddress) throw new Error('state.vending missing — load the machine first (pool-vend-load-role2.mjs)');
const fundLocking = cashAddressToLockingBytecode(state.vending.operatorAddress).bytecode;
const redeem = vendingRedeem({ categoryDisplayHex: state.category, priceSats: BigInt(state.vending.priceSats), operatorLocking: fundLocking });
const vendingLocking = vendingLockingOf(redeem);
assert.equal(binToHex(vendingLocking), state.vending.locking, 'vending locking drift — refusing to buy from a different machine');
const PRICE = BigInt(state.vending.priceSats);

/* find the machine's blank UTXO: scripthash = SINGLE sha256 of the locking, byte-reversed
   (hash256 is the DOUBLE variant — the recorded electrum gotcha, missed on the first run) */
const scriptHash = binToHex(new Uint8Array(sha256a.hash(vendingLocking)).reverse());
const vUtxos = (await rpc('blockchain.scripthash.listunspent', [scriptHash, 'include_tokens'])).filter((u) => u.token_data?.nft?.capability === 'mutable' && !u.token_data.nft.commitment);
if (vUtxos.length === 0) throw new Error('the machine is empty — no blanks at the vending locking');
const machine = PICK ? vUtxos.find((u) => `${u.tx_hash}:${u.tx_pos}` === PICK) : vUtxos[0];
if (!machine) throw new Error('vending-utxo not found at the machine');

/* the buyer's own sats */
const butxos = (await rpc('blockchain.address.listunspent', [buyerAddress])).filter((u) => !u.token_data).sort((a, b) => b.value - a.value);
if (butxos.length === 0) throw new Error('buyer has no plain sats — the buyer pays, that is the point');
const funding = butxos[0];

const CAT_BYTES = hexToBin(state.category);
const txidOf = (t) => binToHex(new Uint8Array(hash256(encodeTransactionBCH(t), sha256a)).reverse());
const tx = {
    version: 2, locktime: 0,
    inputs: [
        { outpointTransactionHash: hexToBin(machine.tx_hash), outpointIndex: machine.tx_pos, sequenceNumber: 0xffffffff, unlockingBytecode: new Uint8Array(0) },
        { outpointTransactionHash: hexToBin(funding.tx_hash), outpointIndex: funding.tx_pos, sequenceNumber: 0xffffffff, unlockingBytecode: new Uint8Array(0) },
    ],
    outputs: [
        /* the blank, delivered to the BUYER's own locking — the blank follows the money */
        { lockingBytecode: buyerLocking, valueSatoshis: BigInt(machine.value), token: { category: CAT_BYTES, amount: 0n, nft: { capability: 'mutable', commitment: new Uint8Array(0) } } },
        /* the exact price, tokenless, to the operator's pinned P2PKH */
        { lockingBytecode: fundLocking, valueSatoshis: PRICE },
        /* buyer change */
        { lockingBytecode: buyerLocking, valueSatoshis: 0n },
    ],
};
/* BARE fee with the EXACT vending-input unlocking length (the 100-B placeholder trap).
   Change = buyer's sats − price − fee; the machine's float returns via out0 unchanged. */
const unl0Len = encodeDataPush(redeem).length;
const probeLen = encodeTransactionBCH({ ...tx, inputs: tx.inputs.map((i, n) => ({ ...i, unlockingBytecode: new Uint8Array(n === 0 ? unl0Len : 100) })) }).length;
tx.outputs[2].valueSatoshis = BigInt(funding.value) - PRICE - BigInt(probeLen) - 600n;
assert(tx.outputs[2].valueSatoshis >= 546n, 'buyer change below dust — fund the buyer with more sats');

const sources = [
    { lockingBytecode: vendingLocking, valueSatoshis: BigInt(machine.value), token: { category: CAT_BYTES, amount: 0n, nft: { capability: 'mutable', commitment: new Uint8Array(0) } } },
    { lockingBytecode: buyerLocking, valueSatoshis: BigInt(funding.value) },
];
/* input 0: the covenant — NO SIGNATURE, push-only redeem (standardness requires push-only) */
tx.inputs[0].unlockingBytecode = new Uint8Array(encodeDataPush(new Uint8Array(redeem)));
/* input 1: the buyer's own P2PKH signature — the only key in this transaction is the buyer's */
const serialization = generateSigningSerializationBCH(
    { inputIndex: 1, sourceOutputs: sources, transaction: tx },
    { coveredBytecode: buyerLocking, signingSerializationType: Uint8Array.of(SigningSerializationTypeBCH.allOutputs) },
    sha256a,
);
const signature = secp.signMessageHashSchnorr(privateKey, hash256(serialization, sha256a));
if (typeof signature === 'string') throw new Error('Schnorr signing failed: ' + signature);
tx.inputs[1].unlockingBytecode = Uint8Array.from([...encodeDataPush(Uint8Array.from([...signature, SigningSerializationTypeBCH.allOutputs])), ...encodeDataPush(publicKey)]);

/* VM-eval input 0 in BOTH modes before broadcast — the covenant must accept on its own */
for (const mode of ['consensus', 'standard']) {
    const st = VMS[mode].evaluate({ inputIndex: 0, sourceOutputs: sources, transaction: tx });
    const top = st.stack?.[st.stack.length - 1];
    const ok = st.error === undefined && st.stack?.length === 1 && top?.length === 1 && top[0] === 1;
    if (!ok) throw new Error(`vending input REJECTED (${mode}): ${st.error}`);
    console.log(`${mode}: ACCEPT · op ${st.metrics.operationCost}/4170400`);
}
const hex = binToHex(encodeTransactionBCH(tx));
const decoded = decodeTransaction(hexToBin(hex));
if (typeof decoded === 'string') throw new Error('buy does not decode: ' + decoded);
const txid = txidOf(tx);
console.log(`buy tx ${txid} · ${hex.length / 2}B — blank ${machine.tx_hash.slice(0, 12)}:${machine.tx_pos} → ${buyerAddress}, price ${PRICE} sats paid`);
if (DRY) { console.log('DRY — not broadcasting.'); process.exit(0); }
console.log('broadcasting…');
console.log('RESULT: ' + await rpc('blockchain.transaction.broadcast', [hex]));

let confirmed = false;
for (let i = 0; i < 60; i += 1) {
    await new Promise((r) => setTimeout(r, 30000));
    try { const m = await rpc('blockchain.transaction.get_merkle', [txid]); confirmed = true; console.log(`\nCONFIRMED block ${m.block_height}`); break; } catch { }
    process.stdout.write('.');
}
if (!confirmed) console.log('\nunconfirmed after 30 min — check chipnet');
process.exit(confirmed ? 0 : 1);
