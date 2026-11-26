// pool-deploy-role2.mjs — DEPLOY the role-2 shielded pool on chipnet, runner-free.
//
// The new pool: the bch-groth16-bn254-sound-native verifier with the pool rules INSIDE role 2
// (the hook), built under OUR solo-ceremony VK. There is NO separate covenant and NO step-UTXO
// fleet: every pool UTXO is locked to the program's own P2SH32(R), and each action is a
// signature-free 3-input spend of that program (inputs 0/1 plain or FT-carrying, input 2 the
// state NFT; the hook enforces the carrier/new-state/payout rules).
//
// Deployment chain (the nito.cash deploy-pool.mjs patterns, empirically verified on-chain
// 2026-11-22/23, adapted to the role-2 shape):
//   tx 1 ANCHOR  — 1-or-more-in / big-change-out P2PKH spend; its TXID = the new category.
//                  NO BN254-range retry here: our circuit takes the category as two 128-bit
//                  limbs (always < r), unlike the wallet's single-field form.
//   (rebuild)    — the program is rebuilt with the REAL category as the hook ctor param
//                  (setCovenant + buildProgram): new code, new R constants, new locking.
//   tx 2 MINT    — spends anchor out0; creates the MINTING NFT (empty commitment — the
//                  live-verified genesis rule) + the 100,000,000 FT supply.
//   tx 3 DEPLOY  — spends the minting NFT → the pool state NFT (MUTABLE, commitment =
//                  seededRootLE ‖ 32 zero bytes — the PUBLIC bootstrap-seed root, verified
//                  byte-for-byte against the chain-deployed v2/v4 genesis commitments) at the
//                  program locking. THE MINTING NFT IS PASSED FORWARD to the wallet (out1) —
//                  required for deposit tagging: the lock txes spend BLANK mutable NFTs
//                  minted from it (pool-tagbatch-role2.mjs) and re-tag them; the first
//                  deployment destroyed the minting NFT, which is why that pool can never
//                  tag. out2 = the full 100M FT supply back to the wallet; out3 = BCH change.
//                  NO fuel outputs: EVERY action (op 1 included) gets its fuel from a TAGGED
//                  LOCK (pool-refill-role2.mjs) built from its proved op file — the exact
//                  client flow, prove → lock → act.
//
// Funding: the APECS faucet HOT wallet (chipnet, bchtest:qzmux3gx…, purpose: operational
// drips, refillable) — key at /home/apecs/.secrets/faucet-hot-wallet.json on the VM (extracted
// from the verified secrets backup). Fee probing uses SIGNED-SIZE placeholders (100 B per
// P2PKH input) × 2 sat/B — the live-diagnosed min-relay lesson.
//
// Usage (VM, from chunked/bn254/bn-native-sound/):
//   BN_VK_FIXTURES=/home/apecs/cov/our.fixtures.json node pool-deploy-role2.mjs --dry
//   BN_VK_FIXTURES=/home/apecs/cov/our.fixtures.json node pool-deploy-role2.mjs
// Writes /home/apecs/cov/role2-pool-state.json (the op builder's input).
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
import { guardRedeem } from './minting-guard.mjs';
import { p2sh32 } from './vm.mjs';

const DRY = process.argv.includes('--dry');
const OUTS = process.env.POOL_3OUT === '1' ? 3 : 2;
const argOf = (n, d) => { const i = process.argv.indexOf(n); return i >= 0 ? process.argv[i + 1] : d; };
/* DEPOSIT-TAGGING REDEPLOY: no deploy-time fuel/deposit outputs — op 1 locks its own. */
const SECRETS = process.argv.includes('--secrets')
    ? process.argv[process.argv.indexOf('--secrets') + 1]
    : '/home/apecs/.secrets/faucet-hot-wallet.json';
const STATE_OUT = argOf('--state-out', '/home/apecs/cov/role2-pool-state.json');
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

/* ---- the PUBLIC bootstrap seeds (role2-seeds.mjs; VERIFIED: seededRootLE reproduces the
   chain-deployed v2/v4 genesis state-NFT commitments byte-for-byte, 551108f6…510f) ---- */
const SEEDS = {
    seededRoot: '6929054123783400311274767094145126358100985226194225817964892295129486332245',
    seededRootLE: '551108f63731bcc628dda2697d70219d103a8c1bf203f2d4aaec6bbea5b4510f',
    genesisCommitment: '551108f63731bcc628dda2697d70219d103a8c1bf203f2d4aaec6bbea5b4510f0000000000000000000000000000000000000000000000000000000000000000',
    genesisLeaves: [
        '12351826192886546690885792605915790291283848718645116437899738538537062803555',
        '7398522746693646650328110604928791171707350116246498951314945102068585381447',
    ],
    bootstrapNotes: [
        { note: { value: '0', ownerPub: '5299619240641551281634865583518297030282874472190772894086521144482721001553', rho: '130842949111883530073146641958534655280', r: '153387697958148631644100398335583547244' }, nk: '1', index: 0 },
        { note: { value: '0', ownerPub: '5299619240641551281634865583518297030282874472190772894086521144482721001553', rho: '130842949111883530073146641958534655281', r: '153387697958149840569920012964758253420' }, nk: '1', index: 1 },
    ],
};

/* ---- wallet + signing ---- */
const secrets = JSON.parse(readFileSync(SECRETS, 'utf8'));
const privateKey = hexToBin(String(secrets.privateKeyHex).replace(/^0x/, '')); /* the file stores the key with an 0x prefix */
const address = secrets.addresses?.chipnet ?? secrets.address;
if (!address.startsWith('bchtest:')) throw new Error('expected a chipnet hot-wallet address, got ' + address);
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
if (sum < 60_000n) throw new Error(`hot wallet has only ${sum} sats in ${picked.length} plain UTXOs — need >= 60000 for the deploy chain`);
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

/* ---- rebuild the program with the REAL category (the hook's ctor param) ---- */
const catOnchain = hexToBin(CATEGORY).slice().reverse();
setCovenant(covenantHook(covenantParams({ categoryOnChain: binToHex(catOnchain) }), OUTS));
const prog = buildProgram();
const programLocking = p2sh32(prog.R);
const programLockingHex = binToHex(programLocking);
console.log('program:     code ' + prog.code.length + 'B sha256 ' + Buffer.from(prog.code).toString('hex').slice(0, 16) + '… · R ' + prog.R.length + 'B · pieces ' + prog.pieces.map((p) => p.length).join('/'));
console.log('program locking: ' + programLockingHex);

/* ---- the MINTING GUARD, built for the REAL category: future pools are BORN GUARDED —
   the deploy locks the minting NFT straight into the guard (out1), so burn and FT-mint
   are consensus-impossible from genesis. The live v2 pool adopted this retroactively
   (pool-guard-adopt-role2.mjs, adopt a5d73b4e…). Suite: minting-guard.mjs 14/14. */
const GUARD_K = 64;
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

/* ---- tx 3: the DEPLOY (pool state NFT + op-1 fee/deposit UTXOs at the program locking) ---- */
const deploy = {
    version: 2,
    inputs: [
        { outpointTransactionHash: hexToBin(mintTxid), outpointIndex: 0, sequenceNumber: 0xffffffff, unlockingBytecode: new Uint8Array(0) }, /* minting NFT */
        { outpointTransactionHash: hexToBin(mintTxid), outpointIndex: 1, sequenceNumber: 0xffffffff, unlockingBytecode: new Uint8Array(0) }, /* 100M FT */
        { outpointTransactionHash: hexToBin(mintTxid), outpointIndex: 2, sequenceNumber: 0xffffffff, unlockingBytecode: new Uint8Array(0) }, /* BCH change */
    ],
    outputs: [
        /* out0: the POOL STATE — mutable NFT, genesis commitment (seededRootLE ‖ 32 zeros), 0 FT */
        { lockingBytecode: programLocking, valueSatoshis: STATE_FLOAT, token: { category: CAT_BYTES, amount: 0n, nft: { capability: 'mutable', commitment: hexToBin(SEEDS.genesisCommitment) } } },
        /* out1: the MINTING NFT, BORN INSIDE THE GUARD — burn and FT-mint are impossible from genesis */
        { lockingBytecode: guardLockingBytes, valueSatoshis: 1000n, token: { category: CAT_BYTES, amount: 0n, nft: { capability: 'minting', commitment: new Uint8Array(0) } } },
        /* out2: the full FT supply back to the wallet (locks carry per-shield deposits from it) */
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
console.log('pool state:  ' + deployTxid + ':0 — category ' + CATEGORY.slice(0, 8) + '… · NFT commitment = seededRoot ‖ zeros · balance 0');

/* decode round-trip all three */
for (const [label, hex] of [['anchor', anchorHex], ['mint', mintHex], ['deploy', deployHex]]) {
    const decoded = decodeTransaction(hexToBin(hex));
    if (typeof decoded === 'string') throw new Error(label + ' tx does not decode: ' + decoded);
}

/* ---- the state file (input to role2-op-witness.mjs + pool-op-role2.mjs) ---- */
const GUARD_STATE = { adoptTxid: deployTxid, txid: deployTxid, vout: 1, sats: 1000, locking: binToHex(guardLockingBytes), redeemLength: guardRedeemBytes.length, K: GUARD_K, bornGuarded: true, policy: 'only possible spend: recreate the minting NFT at the guard + mint K NFT-only empty-commitment blanks to the operator; burn and FT-mint are consensus-impossible (minting-guard.mjs 14/14)' };
const state = {
    id: OUTS === 3 ? 'chipnet-role2-pool3-3out' : 'chipnet-role2-pool',
    network: 'chipnet',
    deployed: new Date().toISOString(),
    program: {
        codeSha256: createHash('sha256').update(prog.code).digest('hex'),
        codeLength: prog.code.length,
        redeemHex: binToHex(prog.R),
        pieces: prog.pieces.map((p) => p.length),
        locking: programLockingHex,
        vk: OUTS === 3 ? 'our 1-of-1 demo setup (build3/pool3_final.zkey sha256 b0177dbe…)' : 'our solo-ceremony zkey (build/pool_final.zkey sha256 4a4e2543…)',
    },
    category: CATEGORY,
    anchorTxid, mintTxid, deployTxid,
    outpoints: {
        state: { txid: deployTxid, vout: 0, sats: Number(STATE_FLOAT), ftAmount: '0', nft: 'mutable', commitment: SEEDS.genesisCommitment },
        /* NO deploy-time fuel: run pool-tagbatch-role2.mjs once, then per action
           role2-op-witness.mjs (prove) → pool-refill-role2.mjs (TAGGED lock) → pool-op-role2.mjs */
        actionInputs: [],
        mintingNFT: { txid: deployTxid, vout: 1, nft: 'minting' },
        guard: GUARD_STATE,
        supply: { txid: deployTxid, vout: 2, ftAmount: SUPPLY.toString() },
    },
    pool: {
        root: SEEDS.seededRoot,
        rootLE: SEEDS.seededRootLE,
        oldNullHex: '00'.repeat(32),
        balance: '0',
        leaves: SEEDS.genesisLeaves,
        notes: SEEDS.bootstrapNotes,
    },
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
console.log('\nDEPLOYED. Poll for confirmations; then pool-tagbatch-role2.mjs (mint tag blanks), then per action: role2-op-witness.mjs (prove) → pool-refill-role2.mjs (TAGGED lock) → pool-op-role2.mjs (build, VM-eval, broadcast).');
process.exit(0);
