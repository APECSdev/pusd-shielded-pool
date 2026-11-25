// minting-guard.mjs — the MINTING-GUARD COVENANT: a P2SH32 script that the pool category's
// minting NFT is locked to, which permits EXACTLY ONE transaction shape on Earth:
//
//   inputs:  [0] the guard UTXO itself (the minting NFT), [1] an operator sats input
//   outputs: [0]     the minting NFT, RECREATED (capability minting, empty commitment,
//                   0 FT), re-locked to THIS SAME GUARD — forever
//            [1..K] K blanks (category + MUTABLE NFT + EMPTY commitment + 0 FT),
//                   each locked to the OPERATOR's P2PKH
//            [K+1]  a TOKENLESS change output locked to the operator's P2PKH
//
// Everything else is consensus-impossible. In particular it is IMPOSSIBLE to:
//   · BURN the minting NFT (out0 must recreate it, at the guard's own locking);
//   · MINT FT (every category-token output is pinned to amount 0; the change output
//     must be tokenless — so not one fungible unit can ever be created);
//   · mint a NON-EMPTY commitment or a none/minting-capability blank (blank shape pinned);
//   · redirect blanks or change to anyone but the operator (lockings pinned);
//   · spend a DIFFERENT token that happens to sit at the guard locking (the active
//     input's own category/capability/commitment/amount are self-checked first);
//   · add inputs or outputs beyond the pinned shape (counts pinned).
//
// The operator signature at the end only gates WHEN a batch may run (anti-griefing);
// it is NOT the security boundary — even a fully compromised operator key cannot burn,
// inflate, or redirect. That is the point: custody moves from "trust the key" to
// "the chain enforces the policy".
//
// Probe-verified introspection facts this script relies on (probe-cap.mjs, 2026-11-24):
//   UTXOTOKCAT(j)/OUTTOKCAT(j) pop an index and push reverse(category) plus a capability
//   byte: 0x02 minting, 0x01 mutable, none for none-capability NFTs and bare FT, and an
//   EMPTY push for tokenless outputs. OUTTOKCOMMIT(j) pushes the commitment as stored
//   (empty commitment → empty push). OUTTOKAMT(j) pushes the FT amount as a minimal VM
//   number (0 → empty push).
//
// LANDMINE DISCIPLINE: every byte sequence entering the VM is a FRESH plain Uint8Array.
import { encodeDataPush } from '@bitauth/libauth';
import { VMS, p2sh32 } from './vm.mjs';

const OP = { NUMEQUALVERIFY: 0x9d, EQUALVERIFY: 0x88, SIZE: 0x82, CHECKSIG: 0xac };
const IX = { INPUTINDEX: 0xc0, TXINPUTCOUNT: 0xc3, TXOUTPUTCOUNT: 0xc4, UTXOBYTECODE: 0xc7, UTXOTOKCAT: 0xce, UTXOTOKCOMMIT: 0xcf, UTXOTOKAMT: 0xd0, OUTBYTECODE: 0xcd, OUTTOKCAT: 0xd1, OUTTOKCOMMIT: 0xd2, OUTTOKAMT: 0xd3 };

/* VM numbers: 0 is the empty push OP_0 (0x00), 1..16 have dedicated opcodes, anything else
   is a minimal-byte push. (OP_RESERVED 0x50 is NOT zero — the first suite run failed on this.) */
const pushNum = (n) => (n === 0 ? [0x00] : n <= 16 ? [0x50 + n] : [...encodeDataPush(new Uint8Array([n & 0xff, ...(n >> 8 ? [n >> 8] : [])]))]);
const pushBytes = (b) => [...encodeDataPush(Uint8Array.from(b))];

/* ── the guard's redeem script ─────────────────────────────────────────────── */
/* params: categoryDisplayHex (natural order), K (blank count), operatorLocking (P2PKH 25 B),
   operatorPubkey (33 B). The capability suffix bytes are probe-verified (0x02/0x01). */
export function guardRedeem({ categoryDisplayHex, K, operatorLocking, operatorPubkey }) {
    const catRev = Buffer.from(categoryDisplayHex, 'hex').reverse();         /* on-chain order */
    const catMinting = new Uint8Array([...catRev, 0x02]);                    /* minting suffix */
    const catMutable = new Uint8Array([...catRev, 0x01]);                    /* mutable suffix */
    const out = [];
    const op = (...bs) => bs.forEach((b) => out.push(...b));

    /* self-orientation: we are input 0 of exactly 2, with exactly K+2 outputs */
    op([IX.INPUTINDEX], pushNum(0), [OP.NUMEQUALVERIFY]);
    op([IX.TXINPUTCOUNT], pushNum(2), [OP.NUMEQUALVERIFY]);
    op([IX.TXOUTPUTCOUNT], pushNum(K + 2), [OP.NUMEQUALVERIFY]);

    /* the ACTIVE input must BE the minting NFT (category + minting + empty commitment + 0 FT)
       — an attacker cannot substitute a different token parked at the guard locking.
       Commitments/empties compare by DIRECT byte equality against OP_0: OP_SIZE is
       NON-POPPING on the BCH-2026 VM (STATUS.md finding 1) and leaks its operand — the
       first suite run died on exactly that. */
    op(pushNum(0), [IX.UTXOTOKCAT], pushBytes(catMinting), [OP.EQUALVERIFY]);
    op(pushNum(0), [IX.UTXOTOKCOMMIT], pushNum(0), [OP.EQUALVERIFY]);
    op(pushNum(0), [IX.UTXOTOKAMT], pushNum(0), [OP.NUMEQUALVERIFY]);

    /* out0: the passthrough — re-locked to THIS GUARD (UTXOBYTECODE(0) is our own locking),
       minting capability, empty commitment, 0 FT. This is the anti-burn core: the minting
       NFT can never leave the guard, never die, and never carry data. */
    op(pushNum(0), [IX.OUTBYTECODE], pushNum(0), [IX.UTXOBYTECODE], [OP.EQUALVERIFY]);
    op(pushNum(0), [IX.OUTTOKCAT], pushBytes(catMinting), [OP.EQUALVERIFY]);
    op(pushNum(0), [IX.OUTTOKCOMMIT], pushNum(0), [OP.EQUALVERIFY]);
    op(pushNum(0), [IX.OUTTOKAMT], pushNum(0), [OP.NUMEQUALVERIFY]);

    /* out1..outK: the blanks — category + MUTABLE + EMPTY commitment + 0 FT, at the
       operator's P2PKH. No FT can hide among them: every one is amount-pinned to 0. */
    for (let j = 1; j <= K; j += 1) {
        op(pushNum(j), [IX.OUTTOKCAT], pushBytes(catMutable), [OP.EQUALVERIFY]);
        op(pushNum(j), [IX.OUTTOKCOMMIT], pushNum(0), [OP.EQUALVERIFY]);
        op(pushNum(j), [IX.OUTTOKAMT], pushNum(0), [OP.NUMEQUALVERIFY]);
        op(pushNum(j), [IX.OUTBYTECODE], pushBytes(operatorLocking), [OP.EQUALVERIFY]);
    }

    /* out[K+1]: the change — TOKENLESS (OUTTOKCAT pushes empty only for tokenless outputs;
       any token of ANY category here would push bytes and fail the size check) and locked
       to the operator. This closes the last FT-mint leak: not even the change can carry
       minted value. */
    op(pushNum(K + 1), [IX.OUTTOKCAT], pushNum(0), [OP.EQUALVERIFY]);
    op(pushNum(K + 1), [IX.OUTBYTECODE], pushBytes(operatorLocking), [OP.EQUALVERIFY]);

    /* operator authorization — gates batch TIMING only (anti-griefing); the shape checks
       above are the security boundary, so even a stolen key cannot burn or inflate. */
    op(pushBytes(operatorPubkey), [OP.CHECKSIG]);
    return Uint8Array.from(out);
}

export const guardLockingOf = (redeem) => p2sh32(redeem);

/* ── the suite: runs on the BCH-2026 VM, consensus + standard ───────────────── */
export async function guardSuite() {
    const { instantiateSecp256k1, instantiateSha256, generateSigningSerializationBCH, hash256, hexToBin, SigningSerializationTypeBCH, binToHex } = await import('@bitauth/libauth');
    const secp = await instantiateSecp256k1();
    const sha256a = await instantiateSha256();

    const CATEGORY = '480e30ff1d3f5f0b6fe9dd2dbe363b1776f61566f29a395628d0b50abd01b9d0';   /* the LIVE v2 pool category */
    const K = 8;                                                                          /* small K for the suite; shape logic is K-generic */
    const priv = hexToBin('11'.repeat(32));                                               /* throwaway key for the suite */
    const pub = secp.derivePublicKeyCompressed(priv);
    const opLock = Uint8Array.from([0x76, 0xa9, 0x14, ...new Uint8Array(20).fill(0xab), 0x88, 0xac]);
    const foreignLock = Uint8Array.from([0x76, 0xa9, 0x14, ...new Uint8Array(20).fill(0xcd), 0x88, 0xac]);
    const redeem = guardRedeem({ categoryDisplayHex: CATEGORY, K, operatorLocking: opLock, operatorPubkey: pub });
    const locking = guardLockingOf(redeem);

    const fresh = (arr) => new Uint8Array(arr);                                           /* landmine discipline */
    const catU = () => fresh(hexToBin(CATEGORY));
    const catRev = () => fresh(Buffer.from(CATEGORY, 'hex').reverse());

    /* the honest guarded batch, with mutation hooks for the rejection cases */
    const mkTx = (mut = {}) => {
        const blank = (j) => ({ lockingBytecode: fresh(opLock), valueSatoshis: 1000n, token: { category: catU(), amount: 0n, nft: { capability: 'mutable', commitment: fresh([]) } }, ...((mut.blankOverrides ?? {})[j] ?? {}) });
        const outputs = [
            { lockingBytecode: fresh(locking), valueSatoshis: 1000n, token: { category: catU(), amount: 0n, nft: { capability: 'minting', commitment: fresh([]) } }, ...(mut.out0 ?? {}) },
            ...Array.from({ length: K }, (_, i) => blank(i + 1)),
            { lockingBytecode: fresh(opLock), valueSatoshis: 500n, ...(mut.change ?? {}) },
        ];
        const inputs = [
            { outpointTransactionHash: new Uint8Array(32).fill(1), outpointIndex: 0, sequenceNumber: 0xffffffff, unlockingBytecode: new Uint8Array(0) },
            { outpointTransactionHash: new Uint8Array(32).fill(2), outpointIndex: 0, sequenceNumber: 0xffffffff, unlockingBytecode: new Uint8Array(0) },
            ...(mut.extraInputs ?? []),
        ];
        const tx = { version: 2, locktime: 0, inputs, outputs: mut.outputs ?? outputs };
        const sources = [
            { lockingBytecode: fresh(locking), valueSatoshis: 1000n, token: { category: catU(), amount: 0n, nft: { capability: 'minting', commitment: fresh([]) } }, ...(mut.input0 ?? {}) },
            { lockingBytecode: fresh(opLock), valueSatoshis: 1_000_000n },
            ...(mut.extraSources ?? []),
        ];
        /* sign input 0 against the REDEEM (P2SH coveredBytecode), all-outputs */
        const serialization = generateSigningSerializationBCH({ inputIndex: 0, sourceOutputs: sources, transaction: tx }, { coveredBytecode: fresh(redeem), signingSerializationType: Uint8Array.of(SigningSerializationTypeBCH.allOutputs) }, sha256a);
        const sig = mut.badSig ? new Uint8Array(65).fill(0x55) : Uint8Array.from([...secp.signMessageHashSchnorr(priv, hash256(serialization, sha256a)), SigningSerializationTypeBCH.allOutputs]);
        if (typeof sig === 'string') throw new Error('sign failed: ' + sig);
        tx.inputs[0].unlockingBytecode = fresh([...encodeDataPush(fresh(sig)), ...encodeDataPush(fresh(redeem))]);
        return { tx, sources };
    };

    const evalCase = (label, expect, mut) => {
        const { tx, sources } = mkTx(mut);
        const res = {};
        for (const mode of ['consensus', 'standard']) {
            const st = VMS[mode].evaluate({ inputIndex: 0, sourceOutputs: sources, transaction: tx });
            const top = st.stack?.[st.stack.length - 1];
            res[mode] = st.error === undefined && st.stack?.length === 1 && top?.length === 1 && top[0] === 1;
            if (st.error !== undefined) res[mode + 'Err'] = String(st.error).slice(0, 60);
        }
        const acc = res.consensus && res.standard;
        const pass = acc === expect;
        console.log(`${pass ? 'ok  ' : 'FAIL'} ${acc ? 'ACCEPT' : 'REJECT'} (want ${expect ? 'ACCEPT' : 'REJECT'})  ${label}${pass ? '' : '  [' + (res.consensusErr ?? res.standardErr) + ']'}`);
        return pass;
    };

    const R = [];
    console.log('--- minting-guard suite (K=' + K + ', category ' + CATEGORY.slice(0, 8) + '…) ---');
    R.push(evalCase('control: the honest guarded batch', true, {}));
    console.log('--- rejections ---');
    R.push(evalCase('BURN: out0 omits the minting NFT (mutable instead)', false, { out0: { token: { category: catU(), amount: 0n, nft: { capability: 'mutable', commitment: new Uint8Array(0) } } } }));
    R.push(evalCase('BURN: out0 carries data in its commitment', false, { out0: { token: { category: catU(), amount: 0n, nft: { capability: 'minting', commitment: new Uint8Array([0xee]) } } } }));
    R.push(evalCase('de-guard: out0 re-locked to a plain P2PKH', false, { out0: { lockingBytecode: fresh(opLock) } }));
    R.push(evalCase('FT MINT: out0 carries a fungible amount', false, { out0: { token: { category: catU(), amount: 100n, nft: { capability: 'minting', commitment: new Uint8Array(0) } } } }));
    R.push(evalCase('FT MINT: a blank carries a fungible amount', false, { blankOverrides: { 1: { token: { category: catU(), amount: 7n, nft: { capability: 'mutable', commitment: new Uint8Array(0) } } } } }));
    R.push(evalCase('FT MINT: the change output carries category FT', false, { change: { token: { category: catU(), amount: 50n } } }));
    R.push(evalCase('FT MINT: the change carries a FOREIGN-category token', false, { change: { token: { category: new Uint8Array(32).fill(9), amount: 1n } } }));
    R.push(evalCase('blank wrong capability (none instead of mutable)', false, { blankOverrides: { 2: { token: { category: catU(), amount: 0n, nft: { capability: 'none', commitment: new Uint8Array(4) } } } } }));
    R.push(evalCase('blank pre-tagged (non-empty commitment)', false, { blankOverrides: { 3: { token: { category: catU(), amount: 0n, nft: { capability: 'mutable', commitment: new Uint8Array(32).fill(3) } } } } }));
    R.push(evalCase('blank redirected to a foreign locking', false, { blankOverrides: { 4: { lockingBytecode: fresh(foreignLock), token: { category: catU(), amount: 0n, nft: { capability: 'mutable', commitment: new Uint8Array(0) } } } } }));
    R.push(evalCase('token substitution at the guard locking (mutable NFT as input)', false, { input0: { token: { category: catU(), amount: 0n, nft: { capability: 'mutable', commitment: new Uint8Array(0) } } } }));
    R.push(evalCase('extra input (3 total)', false, { extraInputs: [{ outpointTransactionHash: new Uint8Array(32).fill(3), outpointIndex: 0, sequenceNumber: 0xffffffff, unlockingBytecode: new Uint8Array(0) }], extraSources: [{ lockingBytecode: fresh(opLock), valueSatoshis: 1000n }] }));
    R.push(evalCase('no signature', false, { badSig: true }));
    console.log(`\n${R.filter(Boolean).length}/${R.length} match expectation`);
    return R.every(Boolean);
}

if (process.argv[1]?.endsWith("minting-guard.mjs")) {
    const ok = await guardSuite();
    process.exit(ok ? 0 : 1);
}
