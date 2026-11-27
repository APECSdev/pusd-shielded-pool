// pool-deploy-role2-v4h.mjs — DEPLOY the C-architecture pool (anchor → mint → deploy,
// born-guarded), runner-free, mainnet or chipnet.
//
// The C architecture (2026-11-27, the no-issuer fix — see pool-test-v4h.mjs's header):
// the pool keeps a FRESH valueless category (state NFT + blanks — OUR key, no third
// party), and the ASSET — real ParyonUSD 2469acc5…, a category we do NOT own — rides the
// H-covenant holdings/deposit pair (in5/in6) once the lifecycle starts. The deploy chain
// itself is IDENTICAL to the v3 flow (anchor → mint → born-guarded deploy) with the v4h
// deltas:
//   - the program: commit96 walks + POOL_HOLDINGS=1 (the 7-input graph pin, 5==6
//     byte-compare) + the holdings-mode hook (check 6 recomputes the actionHash with
//     the ASSET's display category — the circuit witness; V4H-PIVOT-NITO-REVIEW §1);
//   - H = buildHoldingsCovenant (AFTER the program — embeds the program locking hash);
//   - the genesis state NFT commitment is 96 B: LE32(zh[20]) ‖ EMPTY_NULL_ROOT ‖
//     to32LE(0) — [noteRoot ‖ nullSetRoot ‖ balance] — balance 0 at genesis;
//   - the state file carries the ASSET category + the H fields + the 96-B commitment.
//
// The anchor txid IS the pool category (fresh); the asset category is a parameter
// (default 2469acc5… — the user's REAL PUSD). NO ParyonUSD-team asset is ever touched.
//
// Usage (VM, from chunked/bn254/bn-native-sound/):
//   BN_VK_FIXTURES=/home/apecs/cov/our-v3-user3.fixtures.json node pool-deploy-role2-v4h.mjs --dry --network chipnet
//   BN_VK_FIXTURES=/home/apecs/cov/our-v3-user3.fixtures.json node pool-deploy-role2-v4h.mjs --network mainnet --k 16
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
import { buildHoldingsCovenant } from './holdings-covenant.mjs';
import { guardRedeem } from './minting-guard.mjs';
import { p2sh32 } from './vm.mjs';
import { walkV3 } from './pool-tx-v3.mjs';
import { ZH20, LE32_ZH20, EMPTY_NULL_ROOT } from '../../../../pusd-shielded-pool/genesis-v3.mjs';

const DRY = process.argv.includes('--dry');
const argOf = (n, d) => { const i = process.argv.indexOf(n); return i >= 0 ? process.argv[i + 1] : d; };
const NETWORK = argOf('--network', 'chipnet');
if (NETWORK !== 'mainnet' && NETWORK !== 'chipnet') throw new Error('--network must be mainnet|chipnet');
const ELECTRUM_HOST = argOf('--electrum', NETWORK === 'mainnet' ? 'bch.soul-dev.com' : 'chipnet.bch.ninja');
const PREFIX = NETWORK === 'mainnet' ? 'bitcoincash:' : 'bchtest:';
const SECRETS = process.argv.includes('--secrets')
    ? process.argv[process.argv.indexOf('--secrets') + 1]
    : (NETWORK === 'mainnet' ? '/home/apecs/.secrets/mainnet-demo-cycle.json' : '/home/apecs/.secrets/wallet-a-role2-demo.json');
const STATE_OUT = argOf('--state-out', NETWORK === 'mainnet' ? '/home/apecs/cov/role2-pool4-state.mainnet-v4h.json' : '/home/apecs/cov/role2-pool4-state.v4h.json');
const ASSET_CATEGORY = argOf('--asset', '2469acc5afa4b10cb5b5c04afb89c3a3ffd61c5da9c01e26d00951cae2a02544');
const GUARD_K = Number(argOf('--k', '16'));
const STATE_FLOAT = 10_000n;
const SUPPLY = 100_000_000n;

/* ---- electrum (raw TLS JSON-RPC) ---- */
const rpc = (method, params) => new Promise((res, rej) => {
    const sock = tls.connect(50002, ELECTRUM_HOST, { timeout: 12000 });
    let buf = '';
    sock.on('secureConnect', () => sock.write(JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }) + '\n'));
    sock.on('data', (d) => { buf += d.toString(); const line = buf.split('\n')[0];
        if (line) { try { const o = JSON.parse(line); if (o.error) rej(new Error(JSON.stringify(o.error))); else res(o.result); sock.destroy(); } catch { /* wait for more */ } } });
    sock.on('error', rej);
    sock.on('timeout', () => { sock.destroy(); rej(new Error('electrum timeout: ' + method)); });
});

/* ---- wallet + signing ---- */
const secrets = JSON.parse(readFileSync(SECRETS, 'utf8'));
const privateKey = hexToBin(String(secrets.privateKeyHex).replace(/^0x/, ''));
const address = secrets.addresses?.chipnet ?? secrets.address;
if (!address.startsWith(PREFIX)) throw new Error(`expected a ${NETWORK} address, got ` + address);
const sha256a = await instantiateSha256();
const secp = await instantiateSecp256k1();
const publicKey = secrets.publicKeyHex ? hexToBin(secrets.publicKeyHex) : secp.derivePublicKeyCompressed(privateKey);
if (typeof publicKey === 'string') throw new Error('pubkey derivation failed: ' + publicKey);
const fundLocking = cashAddressToLockingBytecode(address).bytecode;

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
const P2PKH_SIGNED = 100;
const probeFee = (transaction) => BigInt(encodeTransactionBCH({ ...transaction, inputs: transaction.inputs.map((i) => ({ ...i, unlockingBytecode: new Uint8Array(P2PKH_SIGNED) })) }).length) * 2n;

/* ---- funding ---- */
const utxos = await rpc('blockchain.address.listunspent', [address, 'include_tokens']);
const plain = utxos.filter((u) => !u.token_data).sort((a, b) => b.value - a.value);
const picked = [];
let sum = 0n;
for (const u of plain) { if (sum >= 80_000n || picked.length >= 20) break; picked.push(u); sum += BigInt(u.value); }
if (sum < 30_000n) throw new Error(`funding wallet has only ${sum} sats in ${picked.length} plain UTXOs — need >= 30000 for the v4h deploy chain`);
console.log(`funding: ${picked.length} plain UTXOs, ${sum} sats (wallet ${address}) · network ${NETWORK} · electrum ${ELECTRUM_HOST}`);

/* ---- tx 1: the CATEGORY ANCHOR (its txid becomes the new POOL category) ---- */
const anchor = {
    version: 2,
    inputs: picked.map((u) => ({ outpointTransactionHash: hexToBin(u.tx_hash), outpointIndex: u.tx_pos, sequenceNumber: 0xffffffff, unlockingBytecode: new Uint8Array(0) })),
    outputs: [
        { lockingBytecode: fundLocking, valueSatoshis: 0n },
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
console.log('anchor tx:  ' + anchorTxid + '  → THE NEW POOL CATEGORY');

/* ---- rebuild the v4h program with the REAL pool category (+ the ASSET category) ---- */
const CATEGORY_ONCHAIN = binToHex(hexToBin(CATEGORY).slice().reverse());
const ASSET_ONCHAIN = binToHex(hexToBin(ASSET_CATEGORY).slice().reverse());
const { walkA, walkB, sizes } = buildWalkScripts(CATEGORY_ONCHAIN, { commit96: true });
const { lockings: WALK_LOCKS, hashes: [walkAHash, walkBHash] } = walkV3(walkA, walkB);
process.env.POOL_NULLDATA_HASHES = JSON.stringify([walkAHash.toString('hex'), walkBHash.toString('hex')]);
process.env.POOL_HOLDINGS = '1';
setCovenant(covenantHook(covenantParams({ categoryOnChain: CATEGORY_ONCHAIN, assetCategoryOnChain: ASSET_ONCHAIN }), 3, { walkAHash, walkBHash, holdings: {} }));
const prog = buildProgram();
const programLocking = p2sh32(prog.R);
const programLockingHex = binToHex(programLocking);
const progLockingHashHex = createHash('sha256').update(Buffer.from(programLocking)).digest('hex');
/* H — after the program (pins the program locking + the walks by hash) */
const HC = buildHoldingsCovenant({ progLockingHashHex, walkAHashHex: walkAHash.toString('hex'), walkBHashHex: walkBHash.toString('hex') });
console.log('v4h program: code ' + prog.code.length + 'B sha256 ' + createHash('sha256').update(prog.code).digest('hex').slice(0, 16) + '… · locking ' + programLockingHex.slice(0, 22) + '…');
console.log('  walks:     walkA ' + sizes.walkA + 'B / walkB ' + sizes.walkB + 'B (commit96) · P2SH32 lockings ' + binToHex(WALK_LOCKS[0]).slice(0, 16) + '… / ' + binToHex(WALK_LOCKS[1]).slice(0, 16) + '…');
console.log('  H:         ' + HC.redeemBytes + 'B redeem · locking ' + HC.lockingHex.slice(0, 22) + '…');
console.log('  asset:     ' + ASSET_CATEGORY.slice(0, 16) + '… (real PUSD — the circuit witness + the FT rider; never minted by us)');

/* ---- the MINTING GUARD, built for the REAL category: BORN GUARDED ---- */
const guardRedeemBytes = guardRedeem({ categoryDisplayHex: CATEGORY, K: GUARD_K, operatorLocking: fundLocking, operatorPubkey: publicKey });
const guardLockingBytes = p2sh32(guardRedeemBytes);
console.log('guard:       redeem ' + guardRedeemBytes.length + 'B · locking ' + binToHex(guardLockingBytes) + ' (K=' + GUARD_K + ')');

/* ---- tx 2: the MINT ---- */
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
console.log('mint tx:     ' + mintTxid + ' (minting NFT + ' + SUPPLY + ' FT of the POOL category ' + CATEGORY.slice(0, 8) + '…)');

/* ---- tx 3: the DEPLOY — the v4h genesis state = empty tree ‖ empty nullifier set ‖ balance 0 ---- */
const GENESIS_COMMITMENT_96 = Buffer.concat([LE32_ZH20, EMPTY_NULL_ROOT, Buffer.alloc(32)]); /* [zh[20] ‖ emptyNullRoot ‖ to32LE(0)] */
const deploy = {
    version: 2,
    inputs: [
        { outpointTransactionHash: hexToBin(mintTxid), outpointIndex: 0, sequenceNumber: 0xffffffff, unlockingBytecode: new Uint8Array(0) },
        { outpointTransactionHash: hexToBin(mintTxid), outpointIndex: 1, sequenceNumber: 0xffffffff, unlockingBytecode: new Uint8Array(0) },
        { outpointTransactionHash: hexToBin(mintTxid), outpointIndex: 2, sequenceNumber: 0xffffffff, unlockingBytecode: new Uint8Array(0) },
    ],
    outputs: [
        /* out0: the POOL STATE — mutable NFT, genesis commitment 96 B, NFT-ONLY */
        { lockingBytecode: programLocking, valueSatoshis: STATE_FLOAT, token: { category: CAT_BYTES, amount: 0n, nft: { capability: 'mutable', commitment: new Uint8Array(GENESIS_COMMITMENT_96) } } },
        /* out1: the MINTING NFT, BORN INSIDE THE GUARD */
        { lockingBytecode: guardLockingBytes, valueSatoshis: 1000n, token: { category: CAT_BYTES, amount: 0n, nft: { capability: 'minting', commitment: new Uint8Array(0) } } },
        /* out2: the full pool-category FT supply back to the wallet */
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
console.log('pool state:  ' + deployTxid + ':0 — pool category ' + CATEGORY.slice(0, 8) + '… · NFT commitment 96 B (zh20 ‖ emptyNull ‖ 0) · NFT-only · balance 0');

for (const [label, hex] of [['anchor', anchorHex], ['mint', mintHex], ['deploy', deployHex]]) {
    const decoded = decodeTransaction(hexToBin(hex));
    if (typeof decoded === 'string') throw new Error(label + ' tx does not decode: ' + decoded);
}

/* ---- the state file ---- */
const GUARD_STATE = { adoptTxid: deployTxid, txid: deployTxid, vout: 1, sats: 1000, locking: binToHex(guardLockingBytes), redeemLength: guardRedeemBytes.length, K: GUARD_K, bornGuarded: true, policy: 'only possible spend: recreate the minting NFT at the guard + mint K NFT-only empty-commitment blanks to the operator; burn and FT-mint are consensus-impossible (minting-guard.mjs 14/14)' };
const state = {
    id: (NETWORK === 'mainnet' ? 'mainnet' : 'chipnet') + '-role2-pool4-v4h',
    network: NETWORK,
    architecture: 'v4h (the C architecture): pool category fresh + the ASSET rides the H-covenant in5/in6 pair; 96-B state commitment [noteRoot ‖ nullSetRoot ‖ balance]',
    deployed: new Date().toISOString(),
    program: {
        codeSha256: createHash('sha256').update(prog.code).digest('hex'),
        codeLength: prog.code.length,
        redeemHex: binToHex(prog.R),
        pieces: prog.pieces.map((p) => p.length),
        locking: programLockingHex,
        vk: 'the three-contribution mini-MPC (Nito → Hush → user; pool4_0003_user.zkey sha256 de7875e3…; VK verification_key_user3.json sha256 f6b49cc0…)',
        walkAHash: walkAHash.toString('hex'),
        walkBHash: walkBHash.toString('hex'),
        walkALockingHex: binToHex(WALK_LOCKS[0]),
        walkBLockingHex: binToHex(WALK_LOCKS[1]),
        walkAScriptHex: binToHex(walkA),
        walkBScriptHex: binToHex(walkB),
        walkASize: sizes.walkA,
        walkBSize: sizes.walkB,
        commit96: true,
        /* the H covenant — the lock funds in5/in6 at this locking; the graph pins
           inputs 5/6 to each other, H pins the program/walks by hash */
        hLockingHex: HC.lockingHex,
        hScriptHex: binToHex(HC.script),
        hLockingHashHex: HC.lockingHashHex,
        progLockingHashHex,
    },
    category: CATEGORY,
    assetCategory: ASSET_CATEGORY,
    anchorTxid, mintTxid, deployTxid,
    outpoints: {
        state: { txid: deployTxid, vout: 0, sats: Number(STATE_FLOAT), ftAmount: '0', nft: 'mutable', commitment: GENESIS_COMMITMENT_96.toString('hex') },
        actionInputs: [],
        mintingNFT: { txid: deployTxid, vout: 1, nft: 'minting' },
        guard: GUARD_STATE,
        supply: { txid: deployTxid, vout: 2, ftAmount: SUPPLY.toString() },
    },
    pool: {
        root: ZH20.toString(),
        rootLE: LE32_ZH20.toString('hex'),
        /* the on-chain 96-B state commitment [noteRoot ‖ nullSetRoot ‖ balance] */
        commitmentHex: GENESIS_COMMITMENT_96.toString('hex'),
        balance: '0',
        leaves: [],
        notes: [],
    },
    nullSet: [],
    fundingAddress: address,
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
console.log('\nDEPLOYED. Poll for confirmations; then pool-tagbatch-role2.mjs (guard blanks), then per action: role2-op-witness-v3.mjs (prove) → pool-refill-role2-v4h.mjs (tagged lock + walks + the H pair) → pool-op-role2-v4h.mjs.');
process.exit(0);

