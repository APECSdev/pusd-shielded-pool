// pool-vend-load-role2.mjs — LOAD the blank VENDING machine: the operator moves N blanks
// from its wallet into the vending covenant (blank-vending.mjs, suite 18/18). From then
// on, acquisition is PERMISSIONLESS — anyone pays the exact pinned price on-chain and the
// blank follows the money; no signature, no permission, no operator involvement per blank.
//
// This closes the distribution chokepoint the deployed guard created: the minting guard
// pins every batch-minted blank to the operator's P2PKH forever (its covenant is
// self-pinning and immortal), so the permissionless layer must sit after the mint. The
// operator's remaining discretion is ONLY how much stock to load — and blanks, once
// bought, are held at the BUYER's own P2PKH, spendable/resellable like postage stamps.
//
// Optionally funds a stranger in the same tx (--fund-addr/--fund-sats) for acquisition
// demos: the stranger then buys through the covenant with blank-buy.mjs using ONLY its
// own key — the definitive on-chain proof that no operator permission exists.
//
// Usage (VM, from chunked/bn254/bn-native-sound/):
//   node pool-vend-load-role2.mjs --count 2 [--fund-addr bchtest:… --fund-sats 50000]
//        [--price 1000] [--state …] [--secrets …] [--dry]
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import tls from 'node:tls';
import {
    binToHex, cashAddressToLockingBytecode, decodeTransaction, encodeDataPush,
    encodeTransactionBCH, generateSigningSerializationBCH, hash256, hexToBin,
    instantiateSecp256k1, instantiateSha256, SigningSerializationTypeBCH,
} from '@bitauth/libauth';
import { vendingRedeem, vendingLockingOf } from './blank-vending.mjs';

const argOf = (n, d) => { const i = process.argv.indexOf(n); return i >= 0 ? process.argv[i + 1] : d; };
const STATE = argOf('--state', '/home/apecs/cov/role2-pool-state.json');
const SECRETS = argOf('--secrets', '/home/apecs/.secrets/faucet-hot-wallet.json');
const N = Number(argOf('--count', '2'));
const PRICE = BigInt(argOf('--price', '1000'));
const FUND_ADDR = argOf('--fund-addr', null);
const FUND_SATS = BigInt(argOf('--fund-sats', '0'));
const DRY = process.argv.includes('--dry');

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
const secrets = JSON.parse(readFileSync(SECRETS, 'utf8'));
const privateKey = hexToBin(String(secrets.privateKeyHex).replace(/^0x/, ''));
const address = secrets.addresses?.chipnet ?? secrets.address;
const sha256a = await instantiateSha256();
const secp = await instantiateSecp256k1();
const publicKey = secrets.publicKeyHex ? hexToBin(secrets.publicKeyHex) : secp.derivePublicKeyCompressed(privateKey);
if (typeof publicKey === 'string') throw new Error('pubkey derivation failed: ' + publicKey);
const fundLocking = cashAddressToLockingBytecode(address).bytecode;   /* the operator's P2PKH (25 B) */
const txidOf = (t) => binToHex(new Uint8Array(hash256(encodeTransactionBCH(t), sha256a)).reverse());
/* BARE fee: all inputs here are plain P2PKH, so the 100-B placeholder is accurate */
const probeFee = (t) => BigInt(encodeTransactionBCH({ ...t, inputs: t.inputs.map((i) => ({ ...i, unlockingBytecode: new Uint8Array(100) })) }).length) * 1n + 600n;

/* the vending covenant for THIS pool: live category, operator = the hot wallet */
const redeem = vendingRedeem({ categoryDisplayHex: state.category, priceSats: PRICE, operatorLocking: fundLocking });
const vendingLocking = vendingLockingOf(redeem);
if (state.vending?.locking && state.vending.locking !== binToHex(vendingLocking)) throw new Error('vending locking drifted from state — refusing');
console.log(`vending: redeem ${redeem.length}B · locking ${binToHex(vendingLocking)} · price ${PRICE} sats · category ${state.category.slice(0, 8)}…`);

/* N blanks at the wallet + one plain sats UTXO for fees */
const utxos = await rpc('blockchain.address.listunspent', [address, 'include_tokens']);
const blanks = utxos.filter((u) => u.token_data?.category === state.category && u.token_data.nft?.capability === 'mutable' && !u.token_data.nft.commitment);
if (blanks.length < N) throw new Error(`only ${blanks.length} blanks at the wallet, need ${N}`);
const plain = utxos.filter((u) => !u.token_data).sort((a, b) => b.value - a.value);
if (plain.length === 0) throw new Error('no plain wallet UTXO for the load fees');

const CAT_BYTES = hexToBin(state.category);
const tx = { version: 2, locktime: 0, inputs: [], outputs: [] };
const sources = [];
for (let i = 0; i < N; i += 1) {
    tx.inputs.push({ outpointTransactionHash: hexToBin(blanks[i].tx_hash), outpointIndex: blanks[i].tx_pos, sequenceNumber: 0xffffffff, unlockingBytecode: new Uint8Array(0) });
    sources.push({ lockingBytecode: fundLocking, valueSatoshis: BigInt(blanks[i].value), token: { category: CAT_BYTES, amount: 0n, nft: { capability: 'mutable', commitment: new Uint8Array(0) } } });
}
tx.inputs.push({ outpointTransactionHash: hexToBin(plain[0].tx_hash), outpointIndex: plain[0].tx_pos, sequenceNumber: 0xffffffff, unlockingBytecode: new Uint8Array(0) });
sources.push({ lockingBytecode: fundLocking, valueSatoshis: BigInt(plain[0].value) });

/* outputs: the N blanks LOADED into the machine (float preserved) */
for (let i = 0; i < N; i += 1) {
    tx.outputs.push({ lockingBytecode: vendingLocking, valueSatoshis: BigInt(blanks[i].value), token: { category: CAT_BYTES, amount: 0n, nft: { capability: 'mutable', commitment: new Uint8Array(0) } } });
}
if (FUND_ADDR) tx.outputs.push({ lockingBytecode: cashAddressToLockingBytecode(FUND_ADDR).bytecode, valueSatoshis: FUND_SATS });
tx.outputs.push({ lockingBytecode: fundLocking, valueSatoshis: 0n });   /* BCH change */
const inSats = sources.reduce((a, s) => a + s.valueSatoshis, 0n);
const outFixed = tx.outputs.slice(0, -1).reduce((a, o) => a + o.valueSatoshis, 0n);
tx.outputs[tx.outputs.length - 1].valueSatoshis = inSats - outFixed - probeFee(tx);
assert(tx.outputs[tx.outputs.length - 1].valueSatoshis >= 546n, 'change below dust — fund the wallet first');

for (let i = 0; i < tx.inputs.length; i += 1) {
    const serialization = generateSigningSerializationBCH(
        { inputIndex: i, sourceOutputs: sources, transaction: tx },
        { coveredBytecode: fundLocking, signingSerializationType: Uint8Array.of(SigningSerializationTypeBCH.allOutputs) },
        sha256a,
    );
    const signature = secp.signMessageHashSchnorr(privateKey, hash256(serialization, sha256a));
    if (typeof signature === 'string') throw new Error('Schnorr signing failed: ' + signature);
    tx.inputs[i].unlockingBytecode = Uint8Array.from([...encodeDataPush(Uint8Array.from([...signature, SigningSerializationTypeBCH.allOutputs])), ...encodeDataPush(publicKey)]);
}
const hex = binToHex(encodeTransactionBCH(tx));
const decoded = decodeTransaction(hexToBin(hex));
if (typeof decoded === 'string') throw new Error('load does not decode: ' + decoded);
const txid = txidOf(tx);
console.log(`load tx ${txid} · ${hex.length / 2}B — ${N} blanks into the vending covenant${FUND_ADDR ? ` + stranger funded ${FUND_SATS} sats` : ''}`);
if (DRY) { console.log('DRY — not broadcasting.'); process.exit(0); }
console.log('broadcasting…');
console.log('RESULT: ' + await rpc('blockchain.transaction.broadcast', [hex]));

let confirmed = false;
for (let i = 0; i < 60; i += 1) {
    await new Promise((r) => setTimeout(r, 30000));
    try { await rpc('blockchain.transaction.get_merkle', [txid]); confirmed = true; break; } catch { }
    process.stdout.write('.');
}
console.log('');
if (!confirmed) throw new Error('load unconfirmed after 30 min — blanks not yet in the machine');
state.vending = { locking: binToHex(vendingLocking), priceSats: Number(PRICE), operatorAddress: address, redeemLength: redeem.length, loadTxid: txid, blanksLoaded: N, loadedAt: new Date().toISOString(), confirmed, policy: 'permissionless first-come-first-served: pay the exact price, the blank follows the money; no signature, no operator involvement (blank-vending.mjs 18/18)' };
if (FUND_ADDR) state.stranger = { ...(state.stranger ?? {}), address: FUND_ADDR, fundedSats: Number(FUND_SATS), fundTxid: txid, fundedAt: new Date().toISOString() };
writeFileSync(STATE, JSON.stringify(state, null, 2) + '\n');
console.log(`state updated: ${N} blanks in the machine${FUND_ADDR ? ` · stranger ${FUND_ADDR} funded` : ''}`);
process.exit(0);
