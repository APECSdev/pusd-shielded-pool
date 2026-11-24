// pool-refill-role2.mjs — refill the role-2 pool's action inputs from the hot wallet.
//
// Every pool action consumes its two non-state inputs (all locked at the program P2SH32) and
// TXINPUTCOUNT==3 forbids an external fee input — so before each action the wallet must
// pre-create fresh UTXOs at the program locking whose sats pay the next action's fee.
// This spends a plain wallet UTXO and creates N plain UTXOs at the program locking
// (optionally carrying FT from the wallet's supply UTXO, for SHIELD-type actions).
//
// Usage (VM, from chunked/bn254/bn-native-sound/):
//   node pool-refill-role2.mjs [--count 2] [--ft 0] [--state /home/apecs/cov/role2-pool-state.json]
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import tls from 'node:tls';
import { binToHex, cashAddressToLockingBytecode, decodeTransaction, encodeDataPush, encodeTransactionBCH, generateSigningSerializationBCH, hash256, hexToBin, instantiateSecp256k1, instantiateSha256, SigningSerializationTypeBCH } from '@bitauth/libauth';

const argOf = (n, d) => { const i = process.argv.indexOf(n); return i >= 0 ? process.argv[i + 1] : d; };
const STATE = argOf('--state', '/home/apecs/cov/role2-pool-state.json');
const SECRETS = argOf('--secrets', '/home/apecs/.secrets/faucet-hot-wallet.json');
const COUNT = Number(argOf('--count', '2'));
const FT = BigInt(argOf('--ft', '0'));
const UTXO_SATS = 16_000n;

const rpc = (method, params) => new Promise((res, rej) => {
    const sock = tls.connect(50002, 'chipnet.bch.ninja', { timeout: 15000 });
    let buf = '';
    sock.on('secureConnect', () => sock.write(JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }) + '\n'));
    sock.on('data', (d) => { buf += d.toString(); const line = buf.split('\n')[0];
        if (line) { try { const o = JSON.parse(line); if (o.error) rej(new Error(JSON.stringify(o.error))); else res(o.result); sock.destroy(); } catch { /* more */ } } });
    sock.on('error', rej); sock.on('timeout', () => { sock.destroy(); rej(new Error('electrum timeout: ' + method)); });
});

const state = JSON.parse(readFileSync(STATE, 'utf8'));
const secrets = JSON.parse(readFileSync(SECRETS, 'utf8'));
const privateKey = hexToBin(String(secrets.privateKeyHex).replace(/^0x/, ''));
const address = secrets.addresses?.chipnet ?? secrets.address;
const sha256a = await instantiateSha256();
const secp = await instantiateSecp256k1();
const publicKey = secp.derivePublicKeyCompressed(privateKey);
const fundLocking = cashAddressToLockingBytecode(address).bytecode;
const programLocking = hexToBin(state.program.locking);
const txidOf = (t) => binToHex(new Uint8Array(hash256(encodeTransactionBCH(t), sha256a)).reverse());
const P2PKH_SIGNED = 100;
const probeFee = (t) => BigInt(encodeTransactionBCH({ ...t, inputs: t.inputs.map((i) => ({ ...i, unlockingBytecode: new Uint8Array(P2PKH_SIGNED) })) }).length) * 2n;

/* funding: a plain wallet UTXO (plus the supply UTXO if FT is requested) */
const utxos = await rpc('blockchain.address.listunspent', [address, 'include_tokens']);
const plain = utxos.filter((u) => !u.token_data).sort((a, b) => b.value - a.value);
if (plain.length === 0) throw new Error('no plain UTXOs at the wallet');
let supply = null;
if (FT > 0n) {
    const tokenUtxos = utxos.filter((u) => u.token_data?.category === state.category && !u.token_data.nft && BigInt(u.token_data.amount) >= FT);
    if (tokenUtxos.length === 0) throw new Error('no FT UTXO at the wallet for the requested shield deposit');
    supply = tokenUtxos.sort((a, b) => BigInt(b.token_data.amount) - BigInt(a.token_data.amount))[0];
}
const fixed = BigInt(COUNT) * UTXO_SATS + (FT > 0n ? 1000n : 0n);
if (BigInt(plain[0].value) < fixed + 2000n + 400n) throw new Error(`largest plain UTXO ${plain[0].value} too small for the refill`);

const inputs = [{ outpointTransactionHash: hexToBin(plain[0].tx_hash), outpointIndex: plain[0].tx_pos, sequenceNumber: 0xffffffff, unlockingBytecode: new Uint8Array(0) }];
if (supply) inputs.push({ outpointTransactionHash: hexToBin(supply.tx_hash), outpointIndex: supply.tx_pos, sequenceNumber: 0xffffffff, unlockingBytecode: new Uint8Array(0) });
const outputs = Array.from({ length: COUNT }, (_, i) => (FT > 0n && i === 0
    ? { lockingBytecode: programLocking, valueSatoshis: UTXO_SATS, token: { category: hexToBin(state.category), amount: FT } }
    : { lockingBytecode: programLocking, valueSatoshis: UTXO_SATS }));
outputs.push({ lockingBytecode: fundLocking, valueSatoshis: 0n }); /* change (BCH; FT change rides below when a supply was spent) */
if (supply && BigInt(supply.token_data.amount) - FT > 0n) outputs.push({ lockingBytecode: fundLocking, valueSatoshis: 1000n, token: { category: hexToBin(state.category), amount: BigInt(supply.token_data.amount) - FT } }); /* a zero-amount FT change output would be invalid — skip if nothing remains */
const tx = { version: 2, locktime: 0, inputs, outputs };
const inSats = BigInt(plain[0].value);
tx.outputs[COUNT].valueSatoshis = inSats - fixed - probeFee(tx);

const sources = [{ lockingBytecode: fundLocking, valueSatoshis: inSats }];
if (supply) sources.push({ lockingBytecode: fundLocking, valueSatoshis: BigInt(supply.value), token: { category: hexToBin(state.category), amount: BigInt(supply.token_data.amount) } });
for (let i = 0; i < tx.inputs.length; i += 1) {
    const serialization = generateSigningSerializationBCH({ inputIndex: i, sourceOutputs: sources, transaction: tx },
        { coveredBytecode: fundLocking, signingSerializationType: Uint8Array.of(SigningSerializationTypeBCH.allOutputs) }, sha256a);
    const signature = secp.signMessageHashSchnorr(privateKey, hash256(serialization, sha256a));
    if (typeof signature === 'string') throw new Error('Schnorr signing failed: ' + signature);
    tx.inputs[i].unlockingBytecode = Uint8Array.from([...encodeDataPush(Uint8Array.from([...signature, SigningSerializationTypeBCH.allOutputs])), ...encodeDataPush(publicKey)]);
}
const hex = binToHex(encodeTransactionBCH(tx));
if (typeof decodeTransaction(hexToBin(hex)) === 'string') throw new Error('refill does not decode');
const txid = txidOf(tx);
console.log(`refill tx ${txid} · ${hex.length / 2}B · ${COUNT} UTXO(s) of ${UTXO_SATS} sats at the program locking${FT > 0n ? ' (input 0 carries ' + FT + ' FT)' : ''}`);

console.log('broadcasting…');
console.log('RESULT: ' + await rpc('blockchain.transaction.broadcast', [hex]));
let confirmed = false;
for (let i = 0; i < 60; i += 1) {
    await new Promise((r) => setTimeout(r, 30000));
    try { await rpc('blockchain.transaction.get_merkle', [txid]); confirmed = true; break; } catch { }
    process.stdout.write('.');
}
console.log('');
if (!confirmed) throw new Error('refill unconfirmed after 30 min — do NOT build the op on it; re-run later');
state.outpoints.actionInputs = Array.from({ length: COUNT }, (_, i) => ({ txid, vout: i, sats: Number(UTXO_SATS), ...(FT > 0n && i === 0 ? { ftAmount: FT.toString() } : {}) }));
writeFileSync(STATE, JSON.stringify(state, null, 2) + '\n');
console.log('state updated: actionInputs = ' + COUNT + ' UTXO(s) of ' + txid.slice(0, 16) + '…');
process.exit(0);
