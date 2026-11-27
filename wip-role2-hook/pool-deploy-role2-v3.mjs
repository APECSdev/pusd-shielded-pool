// pool-deploy-role2-v3.mjs — DEPLOY the V3 role-2 shielded pool on chipnet, runner-free.
//
// The v3 pool (docs/V3-BUILD-2026-11-27.md): the sound verifier + the v3 hook (the
// nullifier-SMT revision) + the TWO walk inputs, built under the pool4 VK. Same
// deployment chain as pool-deploy-role2.mjs (anchor → mint → deploy, born-guarded),
// with the v3 deltas:
//   - the program is built with the WALK SCRIPTS for the REAL category
//     (buildWalkScripts — the walk scripts pin UTXOTOKCAT(2) == category+0x01),
//     the GRAPH pin (POOL_NULLDATA_HASHES: TXINPUTCOUNT == 5, the walk lockings
//     SHA256-pinned inside the graph) and the v3 hook (check 4w walk-locking pins,
//     fold check 7 REMOVED, check 10 = length + first half);
//   - the genesis state NFT commitment = LE32(zh[20]) ‖ EMPTY_NULL_ROOT — the EMPTY
//     note tree ‖ the EMPTY nullifier SMT (genesis-v3.mjs, computed from first
//     principles). NO BOOTSTRAP SEEDS: the first notes enter via a DEPOSIT;
//   - the state file is the v3 shape (role2-pool4-state.json): pool.leaves [],
//     pool.notes [], nullSet [] — the spent-SMT-key list role2-op-witness-v3.mjs
//     advances per action;
//   - the walk lockings + hashes are recorded in the state file (the lock tool
//     creates the two walk-data dust UTXOs per action; the action builder reads
//     them back for the walk source outputs).
//
// Every pool UTXO is locked to the program's own P2SH32(R); actions are the
// signature-free 5-input spends (fuel pair, state NFT, walkA, walkB).
//
// Usage (VM, from chunked/bn254/bn-native-sound/):
//   BN_VK_FIXTURES=/home/apecs/cov/our-v3.fixtures.json node pool-deploy-role2-v3.mjs --dry
//   BN_VK_FIXTURES=/home/apecs/cov/our-v3.fixtures.json node pool-deploy-role2-v3.mjs
// Writes /home/apecs/cov/role2-pool4-state.json (the v3 op builder's input).
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import tls from 'node:tls';
import {
    binToHex, cashAddressToLockingBytecode, decodeTransaction, encodeDataPush,
    encodeTransactionBCH, generateSigningSerializationBCH, hash256, hexToBin,
    instantiateSecp256k1, instantiateSha256, SigningSerializationTypeBCH,
} from '@bitauth/libauth';
import { buildProgram, setCovenant } from './script.mjs';
import { covenantHook, covenantParams } from './pool-hook.mjs';
import { buildWalkScripts } from './walk-scripts.mjs';
import { guardRedeem } from './minting-guard.mjs';
import { p2sh32 } from './vm.mjs';
import { walkV3 } from './pool-tx-v3.mjs';
import { ZH20, LE32_ZH20, EMPTY_NULL_ROOT, GENESIS_COMMITMENT } from '../../../../pusd-shielded-pool/genesis-v3.mjs';

const DRY = process.argv.includes('--dry');
const argOf = (n, d) => { const i = process.argv.indexOf(n); return i >= 0 ? process.argv[i + 1] : d; };
const SECRETS = process.argv.includes('--secrets')
    ? process.argv[process.argv.indexOf('--secrets') + 1]
    : '/home/apecs/.secrets/wallet-a-role2-demo.json';
const STATE_OUT = argOf('--state-out', '/home/apecs/cov/role2-pool4-state.json');
const GUARD_K = Number(argOf('--k', '64'));
const STATE_FLOAT = 10_000n;                // sats riding on the state NFT (fee float)
const SUPPLY = 100_000_000n;

/* ---- electrum (raw TLS JSON-RPC; chipnet.bch.ninja:50002 — Fulcrum 2.1.3, live-verified) ---- */
const rpc = (method, params) => new Promise((res, rej) => {
    const sock = tls.connect(50002, 'chipnet.bch.ninja', { timeout: 12000 });
    let buf = '';
    sock.on('secureConnect', () => sock.write(JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }) + '\n'));
    sock.on('data', (d) => { buf += d.toString(); const line = buf.split('\n')[0];
        if (line) { try { const o = JSON.parse(line); if (o.error) rej(new Error(JSON.stringify(o.error))); else res(o.result); sock.destroy(); } catch { /* wait for more */ } } });
    sock.on('error', rej);
    sock.on('timeout', () => { sock.destroy(); rej(new Error('electrum timeout: ' + method)); });
});

/* ---- wallet + signing ---- */
const secrets = JSON.parse(readFileSync(SECRETS, 'utf8'));
const privateKey = hexToBin(String(secrets.privateKeyHex).replace(/^0x/, '')); /* the file stores the key with an 0x prefix */
const address = secrets.addresses?.chipnet ?? secrets.address;
if (!address.startsWith('bchtest:')) throw new Error('expected a chipnet address, got ' + address);
const sha256a = await instantiateSha256();
const secp = await instantiateSecp256k1();
const publicKey = secrets.publicKeyHex ? hexToBin(secrets.publicKeyHex) : secp.derivePublicKeyCompressed(privateKey);
if (typeof publicKey === 'string') throw new Error('pubkey derivation failed: ' + publicKey);
const fundLocking = cashAddressToLockingBytecode(address).bytecode;

/* BCH txid = double-sha256 of the FULL SIGNED tx, ONCE (live-verified 2026-11-22). */
const txidOf = (transaction) => binToHex(new Uint8Array(hash256(encodeTransactionBCH(transaction), sha256a)).reverse());

const signInputs = async (transaction, sourceOutputs) => {
    for (let i = 0; i < transaction.inputs.length; i += 1) {
        const serialization = generateSigningSerializationBCH(
            { inputIndex: i, sourceOutputs, transaction },
            { coveredBytecode: fundLocking, signingSerializationType: Uint8Array.of(SigningSerializationTypeBCH.allOutputs) },
            sha256a,
        );
        const digest = hash256(serialization, sha256a);
        const signature = secp.signMessageHashSchnorr(privateKey, digest);
        if (typeof signature === 'string') throw new Error('Schnorr signing failed: ' + signature);
        const sigWithType = Uint8Array.from([...signature, SigningSerializationTypeBCH.allOutputs]);
        transaction.inputs[i].unlockingBytecode = Uint8Array.from([...encodeDataPush(sigWithType), ...encodeDataPush(publicKey)]);
    }
};

/* fee probe with SIGNED-SIZE placeholder unlockings (the live-diagnosed min-relay lesson) */
const P2PKH_SIGNED = 100;
const probeFee = (transaction) => BigInt(encodeTransactionBCH({ ...transaction, inputs: transaction.inputs.map((i) => ({ ...i, unlockingBytecode: new Uint8Array(P2PKH_SIGNED) })) }).length) * 2n;

/* ---- funding ---- */
const utxos = await rpc('blockchain.address.listunspent', [address, 'include_tokens']);
const plain = utxos.filter((u) => !u.token_data).sort((a, b) => b.value - a.value);
const picked = [];
let sum = 0n;
for (const u of plain) { if (sum >= 80_000n || picked.length >= 20) break; picked.push(u); sum += BigInt(u.value); }
if (sum < 30_000n) throw new Error(`funding wallet has only ${sum} sats in ${picked.length} plain UTXOs — need >= 30000 for the v3 deploy chain`);
console.log(`funding: ${picked.length} plain UTXOs, ${sum} sats (wallet ${address})`);

/* ---- tx 1: the CATEGORY ANCHOR (its txid becomes the new category) ---- */
const anchor = {
    version: 2,
    inputs: picked.map((u) => ({ outpointTransactionHash: hexToBin(u.tx_hash), outpointIndex: u.tx_pos, sequenceNumber: 0xffffffff, unlockingBytecode: new Uint8Array(0) })),
    outputs: [
        { lockingBytecode: fundLocking, valueSatoshis: 0n }, /* the BIG output the mint spends as vin[0].vout=0 */
        { lockingBytecode: fundLocking, valueSatoshis: 1000n },
    ],
    locktime: 0,
};
anchor.outputs[0].valueSatoshis = sum - 1000n - probeFee(anchor);
await signInputs(anchor, picked.map((u) => ({ lockingBytecode: fundLocking, valueSatoshis: BigInt(u.value) })));
const anchorHex = binToHex(encodeTransactionBCH(anchor));
const anchorTxid = txidOf(anchor);
const CATEGORY = anchorTxid;
const CAT_BYTES = hexToBin(CATEGORY);
console.log('anchor tx:  ' + anchorTxid + '  → THE NEW CATEGORY');

/* ---- rebuild the v3 program with the REAL category: walk scripts + graph pin + v3 hook ---- */
const CATEGORY_ONCHAIN = binToHex(hexToBin(CATEGORY).slice().reverse());
const { walkA, walkB, sizes } = buildWalkScripts(CATEGORY_ONCHAIN);
/* v3.1: the walk UTXOs are P2SH32-WRAPPED (the raw form is relay-nonstandard,
   measured on chipnet 2026-11-27); the 4w/graph pins hash the ON-CHAIN lockings */
const { lockings: WALK_LOCKS, hashes: [walkAHash, walkBHash] } = walkV3(walkA, walkB);
process.env.POOL_NULLDATA_HASHES = JSON.stringify([walkAHash.toString('hex'), walkBHash.toString('hex')]);
setCovenant(covenantHook(covenantParams({ categoryOnChain: CATEGORY_ONCHAIN }), 3, { walkAHash, walkBHash }));
const prog = buildProgram();
const programLocking = p2sh32(prog.R);
const programLockingHex = binToHex(programLocking);
console.log('v3 program:  code ' + prog.code.length + 'B sha256 ' + createHash('sha256').update(prog.code).digest('hex').slice(0, 16) + '… · R ' + prog.R.length + 'B · pieces ' + prog.pieces.map((p) => p.length).join('/'));
console.log('  walks:      walkA ' + sizes.walkA + 'B / walkB ' + sizes.walkB + 'B scripts · P2SH32 lockings ' + binToHex(WALK_LOCKS[0]).slice(0, 16) + '… / ' + binToHex(WALK_LOCKS[1]).slice(0, 16) + '…');
console.log('program locking: ' + programLockingHex);

/* ---- the MINTING GUARD, built for the REAL category: BORN GUARDED (pool-deploy-role2.mjs pattern) ---- */
const guardRedeemBytes = guardRedeem({ categoryDisplayHex: CATEGORY, K: GUARD_K, operatorLocking: fundLocking, operatorPubkey: publicKey });
const guardLockingBytes = p2sh32(guardRedeemBytes);
console.log('guard:        redeem ' + guardRedeemBytes.length + 'B · locking ' + binToHex(guardLockingBytes) + ' (K=' + GUARD_K + ')');

/* ---- tx 2: the MINT (genesis token rules, live-verified 2026-11-22) ---- */
const mint = {
    version: 2,
    inputs: [{ outpointTransactionHash: hexToBin(anchorTxid), outpointIndex: 0, sequenceNumber: 0xffffffff, unlockingBytecode: new Uint8Array(0) }],
    outputs: [
        { lockingBytecode: fundLocking, valueSatoshis: 1000n, token: { category: CAT_BYTES, amount: 0n, nft: { capability: 'minting', commitment: new Uint8Array(0) } } },
        { lockingBytecode: fundLocking, valueSatoshis: 1000n, token: { category: CAT_BYTES, amount: SUPPLY } },
    ],
    locktime: 0,
};
mint.outputs.push({ lockingBytecode: fundLocking, valueSatoshis: BigInt(anchor.outputs[0].valueSatoshis) - 2000n - probeFee(mint) });
await signInputs(mint, [{ lockingBytecode: fundLocking, valueSatoshis: BigInt(anchor.outputs[0].valueSatoshis) }]);
const mintHex = binToHex(encodeTransactionBCH(mint));
const mintTxid = txidOf(mint);
console.log('mint tx:     ' + mintTxid + ' (minting NFT + ' + SUPPLY + ' FT of ' + CATEGORY.slice(0, 8) + '…)');

/* ---- tx 3: the DEPLOY — the v3 genesis state = the EMPTY tree ‖ the EMPTY nullifier set ---- */
const deploy = {
    version: 2,
    inputs: [
        { outpointTransactionHash: hexToBin(mintTxid), outpointIndex: 0, sequenceNumber: 0xffffffff, unlockingBytecode: new Uint8Array(0) }, /* minting NFT */
        { outpointTransactionHash: hexToBin(mintTxid), outpointIndex: 1, sequenceNumber: 0xffffffff, unlockingBytecode: new Uint8Array(0) }, /* 100M FT */
        { outpointTransactionHash: hexToBin(mintTxid), outpointIndex: 2, sequenceNumber: 0xffffffff, unlockingBytecode: new Uint8Array(0) }, /* BCH change */
    ],
    outputs: [
        /* out0: the POOL STATE — mutable NFT, genesis commitment = LE32(zh[20]) ‖ EMPTY_NULL_ROOT, 0 FT */
        { lockingBytecode: programLocking, valueSatoshis: STATE_FLOAT, token: { category: CAT_BYTES, amount: 0n, nft: { capability: 'mutable', commitment: new Uint8Array(GENESIS_COMMITMENT) } } },
        /* out1: the MINTING NFT, BORN INSIDE THE GUARD — burn and FT-mint are impossible from genesis */
        { lockingBytecode: guardLockingBytes, valueSatoshis: 1000n, token: { category: CAT_BYTES, amount: 0n, nft: { capability: 'minting', commitment: new Uint8Array(0) } } },
        /* out2: the full FT supply back to the wallet (locks carry per-deposit FT from it) */
        { lockingBytecode: fundLocking, valueSatoshis: 1000n, token: { category: CAT_BYTES, amount: SUPPLY } },
    ],
    locktime: 0,
};
const deployFixed = STATE_FLOAT + 1000n + 1000n;
deploy.outputs.push({ lockingBytecode: fundLocking, valueSatoshis: BigInt(mint.outputs[2].valueSatoshis) - deployFixed - probeFee(deploy) });
const deploySources = [
    { lockingBytecode: fundLocking, valueSatoshis: 1000n, token: { category: CAT_BYTES, amount: 0n, nft: { capability: 'minting', commitment: new Uint8Array(0) } } },
    { lockingBytecode: fundLocking, valueSatoshis: 1000n, token: { category: CAT_BYTES, amount: SUPPLY } },
    { lockingBytecode: fundLocking, valueSatoshis: BigInt(mint.outputs[2].valueSatoshis) },
];
await signInputs(deploy, deploySources);
const deployHex = binToHex(encodeTransactionBCH(deploy));
const deployTxid = txidOf(deploy);
console.log('deploy tx:   ' + deployTxid + ' (' + deployHex.length / 2 + 'B)');
console.log('pool state:  ' + deployTxid + ':0 — category ' + CATEGORY.slice(0, 8) + '… · NFT commitment = LE32(zh[20]) ‖ EMPTY_NULL_ROOT (' + GENESIS_COMMITMENT.length + 'B) · balance 0');

/* decode round-trip all three */
for (const [label, hex] of [['anchor', anchorHex], ['mint', mintHex], ['deploy', deployHex]]) {
    const decoded = decodeTransaction(hexToBin(hex));
    if (typeof decoded === 'string') throw new Error(label + ' tx does not decode: ' + decoded);
}

/* ---- the state file (input to role2-op-witness-v3.mjs + pool-op-role2-v3.mjs) ---- */
const GUARD_STATE = { adoptTxid: deployTxid, txid: deployTxid, vout: 1, sats: 1000, locking: binToHex(guardLockingBytes), redeemLength: guardRedeemBytes.length, K: GUARD_K, bornGuarded: true, policy: 'only possible spend: recreate the minting NFT at the guard + mint K NFT-only empty-commitment blanks to the operator; burn and FT-mint are consensus-impossible (minting-guard.mjs 14/14)' };
const state = {
    id: 'chipnet-role2-pool4-v3',
    network: 'chipnet',
    deployed: new Date().toISOString(),
    program: {
        codeSha256: createHash('sha256').update(prog.code).digest('hex'),
        codeLength: prog.code.length,
        redeemHex: binToHex(prog.R),
        pieces: prog.pieces.map((p) => p.length),
        locking: programLockingHex,
        vk: 'the v3 1-of-1 demo setup (build4/pool4_final.zkey sha256 942f8fc5327191da4a98bfbd81b74f87bd6f79267efb2d3067ac6cd0175a723a — CHIPNET-ONLY until the mini-MPC settles)',
        walkAHash: walkAHash.toString('hex'),
        walkBHash: walkBHash.toString('hex'),
        /* the ON-CHAIN walk lockings (P2SH32-wrapped scripts, v3.1) — the lock
           tool creates the walk-data UTXOs at these; the op builder drift-checks */
        walkALockingHex: binToHex(WALK_LOCKS[0]),
        walkBLockingHex: binToHex(WALK_LOCKS[1]),
        /* the raw walk scripts (the redeem pushes riding the walk unlockings) */
        walkAScriptHex: binToHex(walkA),
        walkBScriptHex: binToHex(walkB),
        walkASize: sizes.walkA,
        walkBSize: sizes.walkB,
    },
    category: CATEGORY,
    anchorTxid, mintTxid, deployTxid,
    outpoints: {
        state: { txid: deployTxid, vout: 0, sats: Number(STATE_FLOAT), ftAmount: '0', nft: 'mutable', commitment: GENESIS_COMMITMENT.toString('hex') },
        /* NO deploy-time fuel: run pool-tagbatch-role2.mjs once (guard blanks), then per
           action role2-op-witness-v3.mjs (prove) → pool-refill-role2-v3.mjs (the TAGGED
           lock + the walk-data dust UTXOs) → pool-op-role2-v3.mjs */
        actionInputs: [],
        mintingNFT: { txid: deployTxid, vout: 1, nft: 'minting' },
        guard: GUARD_STATE,
        supply: { txid: deployTxid, vout: 2, ftAmount: SUPPLY.toString() },
    },
    pool: {
        root: ZH20.toString(),
        rootLE: LE32_ZH20.toString('hex'),
        /* the on-chain 64-B state commitment (noteRoot ‖ nullSetRoot) — the op builder
           cross-checks every action's walk anchor against it and advances it per op */
        commitmentHex: GENESIS_COMMITMENT.toString('hex'),
        balance: '0',
        leaves: [],
        notes: [],
    },
    /* the v3 nullifier SMT: the spent-key list (32-B LE hex) — EMPTY at genesis */
    nullSet: [],
    fundingAddress: address,
    /* top-level alias: pool-tagbatch-role2.mjs reads state.guard (the adopt script writes it there);
       a born-guarded deploy must expose the same shape. */
    guard: GUARD_STATE,
};
writeFileSync(STATE_OUT, JSON.stringify(state, null, 2) + '\n');
console.log('state:       ' + STATE_OUT);

if (DRY) {
    console.log('\nDRY — not broadcasting. HEX sizes: anchor ' + anchorHex.length / 2 + 'B, mint ' + mintHex.length / 2 + 'B, deploy ' + deployHex.length / 2 + 'B');
    process.exit(0);
}

console.log('\nbroadcasting anchor…');
console.log('ANCHOR RESULT: ' + await rpc('blockchain.transaction.broadcast', [anchorHex]));
console.log('broadcasting mint…');
console.log('MINT RESULT: ' + await rpc('blockchain.transaction.broadcast', [mintHex]));
console.log('broadcasting deploy…');
console.log('DEPLOY RESULT: ' + await rpc('blockchain.transaction.broadcast', [deployHex]));
console.log('\nDEPLOYED. Poll for confirmations; then pool-tagbatch-role2.mjs (guard blanks), then per action: role2-op-witness-v3.mjs (prove) → pool-refill-role2-v3.mjs (tagged lock + walk-data UTXOs) → pool-op-role2-v3.mjs (build, VM-eval ×5 inputs, broadcast).');
process.exit(0);
