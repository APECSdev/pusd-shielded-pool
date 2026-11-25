// blank-vending.mjs — the BLANK-VENDING COVENANT: permissionless, on-chain, first-come-
// first-served acquisition of tag blanks. This closes the operator-distribution chokepoint:
// the deployed minting guard pins batch-minted blanks to the operator's P2PKH forever
// (out-locking baked into an IMMORTAL, self-pinning covenant), so the permissionless layer
// must sit AFTER the mint. The operator LOADS blanks into this covenant with plain wallet
// sends; from then on ANYONE can take one by paying the pinned price — no signature, no
// permission, no operator involvement. The script IS the authorization.
//
//   inputs:  [0] the vending UTXO — a BLANK (category + MUTABLE NFT + EMPTY commitment +
//               0 FT) locked to this covenant
//            [1] the buyer's funding input (ANY locking, must be TOKENLESS — this is the
//               input that pays, and the blank is delivered to ITS locking)
//   outputs: [0] the blank, RECREATED at the BUYER's own locking (the blank follows the
//               money), float preserved
//            [1] EXACTLY priceSats, tokenless, to the operator's P2PKH (the price pin)
//            [2] tokenless change, anywhere the buyer directs it
//
// The elegant rule is OUTBYTECODE(0) == UTXOBYTECODE(1): whoever pays receives. An attacker
// cannot underpay, overpay, redirect the payment or the blank, extract the float, receive
// a minting-capability or pre-tagged NFT, or dispense a foreign token parked at the
// vending locking. They CAN only do the honest thing: pay the exact price for the exact
// blank to their own address.
//
// No CHECKSIG anywhere: a blank is INERT at a P2PKH — it authorizes nothing by itself; the
// action still requires proof knowledge of notes + fuel tags + the user's own sats.
// Blank inflation is not value inflation; rate-limiting and spam-resistance come from
// fees, not from gatekeeping the blank supply.
//
// Introspection opcodes verified from libauth source (bch-2023-opcodes.js, inherited by
// the BCH-2026 VM): OP_UTXOVALUE = 198 = 0xc6 (pops j, pushes sources[j].valueSatoshis),
// OP_OUTPUTVALUE = 204 = 0xcc (pops j, pushes outputs[j].valueSatoshis). Token-capability
// bytes are probe-verified (probe-cap.mjs): UTXOTOKCAT/OUTTOKCAT push reverse(category)
// + 0x02 minting / 0x01 mutable / bare reversed category for none-capability and bare FT /
// EMPTY push for tokenless. OUTTOKCOMMIT pushes the commitment as stored.
//
// LANDMINE DISCIPLINE: every byte sequence entering the VM is a FRESH plain Uint8Array.
import { encodeDataPush } from '@bitauth/libauth';
import { VMS, p2sh32 } from './vm.mjs';

const OP = { NUMEQUALVERIFY: 0x9d, EQUALVERIFY: 0x88 };
const IX = { INPUTINDEX: 0xc0, TXINPUTCOUNT: 0xc3, TXOUTPUTCOUNT: 0xc4, UTXOVALUE: 0xc6, UTXOBYTECODE: 0xc7, UTXOTOKCAT: 0xce, UTXOTOKCOMMIT: 0xcf, UTXOTOKAMT: 0xd0, OUTBYTECODE: 0xcd, OUTTOKCAT: 0xd1, OUTTOKCOMMIT: 0xd2, OUTTOKAMT: 0xd3, OUTPUTVALUE: 0xcc };

/* VM numbers: 0 is the empty push OP_0 (0x00), 1..16 have dedicated opcodes, anything else
   is a minimal little-endian push with a 0x00 sign pad when the high bit is set.
   (OP_RESERVED 0x50 is NOT zero — the guard suite died on exactly this.) */
const pushNum = (n) => (n === 0 ? [0x00] : n <= 16 ? [0x50 + n] : vmIntBytes(n));
const vmIntBytes = (n) => { let x = BigInt(n); const b = []; while (x > 0n) { b.push(Number(x & 0xffn)); x >>= 8n; } if (b[b.length - 1] >= 0x80) b.push(0x00); return [...encodeDataPush(Uint8Array.from(b))]; };
const pushBytes = (b) => [...encodeDataPush(Uint8Array.from(b))];

/* ── the vending redeem script ──────────────────────────────────────────────── */
/* params: categoryDisplayHex (natural order), priceSats (exact, positive), operatorLocking
   (P2PKH bytes — the price destination, baked in). */
export function vendingRedeem({ categoryDisplayHex, priceSats, operatorLocking }) {
    if (priceSats <= 0n) throw new Error('priceSats must be positive');
    const catRev = Buffer.from(categoryDisplayHex, 'hex').reverse();         /* on-chain order */
    const catMutable = new Uint8Array([...catRev, 0x01]);                    /* mutable suffix */
    const out = [];
    const op = (...bs) => bs.forEach((b) => out.push(...b));

    /* self-orientation: we are input 0 of exactly 2, with exactly 3 outputs */
    op([IX.INPUTINDEX], pushNum(0), [OP.NUMEQUALVERIFY]);
    op([IX.TXINPUTCOUNT], pushNum(2), [OP.NUMEQUALVERIFY]);
    op([IX.TXOUTPUTCOUNT], pushNum(3), [OP.NUMEQUALVERIFY]);

    /* the ACTIVE input must BE a blank (category + mutable + EMPTY commitment + 0 FT) —
       an attacker cannot dispense a foreign or minting-capability token parked at the
       vending locking. Commitments/empties compare by DIRECT byte equality against OP_0
       (OP_SIZE is non-popping on this VM and leaks its operand). */
    op(pushNum(0), [IX.UTXOTOKCAT], pushBytes(catMutable), [OP.EQUALVERIFY]);
    op(pushNum(0), [IX.UTXOTOKCOMMIT], pushNum(0), [OP.EQUALVERIFY]);
    op(pushNum(0), [IX.UTXOTOKAMT], pushNum(0), [OP.NUMEQUALVERIFY]);

    /* the funding input must be TOKENLESS — the buyer pays in plain sats only */
    op(pushNum(1), [IX.UTXOTOKCAT], pushNum(0), [OP.EQUALVERIFY]);

    /* out0: the blank, delivered to WHOEVER PAID (the funding input's own locking) —
       the blank follows the money. Shape pinned: same category, mutable, EMPTY
       commitment, 0 FT, float preserved byte-for-value. */
    op(pushNum(0), [IX.OUTBYTECODE], pushNum(1), [IX.UTXOBYTECODE], [OP.EQUALVERIFY]);
    op(pushNum(0), [IX.OUTTOKCAT], pushBytes(catMutable), [OP.EQUALVERIFY]);
    op(pushNum(0), [IX.OUTTOKCOMMIT], pushNum(0), [OP.EQUALVERIFY]);
    op(pushNum(0), [IX.OUTTOKAMT], pushNum(0), [OP.NUMEQUALVERIFY]);
    op(pushNum(0), [IX.OUTPUTVALUE], pushNum(0), [IX.UTXOVALUE], [OP.NUMEQUALVERIFY]);

    /* out1: the PRICE — EXACTLY priceSats, tokenless, to the operator's P2PKH.
       No underpay, no overpay, no redirect, no token smuggled inside the payment. */
    op(pushNum(1), [IX.OUTPUTVALUE], vmIntBytes(priceSats), [OP.NUMEQUALVERIFY]);
    op(pushNum(1), [IX.OUTBYTECODE], pushBytes(operatorLocking), [OP.EQUALVERIFY]);
    op(pushNum(1), [IX.OUTTOKCAT], pushNum(0), [OP.EQUALVERIFY]);

    /* out2: tokenless change to anywhere the buyer directs it (their money, their
       choice of address). Not one fungible unit can ride any output of this machine. */
    op(pushNum(2), [IX.OUTTOKCAT], pushNum(0), [OP.EQUALVERIFY]);

    /* Every check above is a *VERIFY (pushes nothing on success), so a fully-passing
       execution would end with an EMPTY stack — but P2SH requires the final stack to be
       exactly [truthy]. Unlike the guard (whose CHECKSIG supplies the final push), this
       signature-free script must push its own success bit once every VERIFY has passed. */
    op([0x51]);                                                                  /* OP_1 */
    return Uint8Array.from(out);
}

export const vendingLockingOf = (redeem) => p2sh32(redeem);

/* ── the suite: runs on the BCH-2026 VM, consensus + standard ───────────────── */
export async function vendingSuite() {
    const { hexToBin } = await import('@bitauth/libauth');

    const CATEGORY = '480e30ff1d3f5f0b6fe9dd2dbe363b1776f61566f29a395628d0b50abd01b9d0';   /* the LIVE v2 pool category */
    const PRICE = 1000n;
    const opLock = Uint8Array.from([0x76, 0xa9, 0x14, ...new Uint8Array(20).fill(0xab), 0x88, 0xac]);
    const buyerLock = Uint8Array.from([0x76, 0xa9, 0x14, ...new Uint8Array(20).fill(0x77), 0x88, 0xac]);
    const foreignLock = Uint8Array.from([0x76, 0xa9, 0x14, ...new Uint8Array(20).fill(0xcd), 0x88, 0xac]);
    const redeem = vendingRedeem({ categoryDisplayHex: CATEGORY, priceSats: PRICE, operatorLocking: opLock });
    const locking = vendingLockingOf(redeem);

    const fresh = (arr) => new Uint8Array(arr);                                           /* landmine discipline */
    const catU = () => fresh(hexToBin(CATEGORY));
    const blankAt = (lock, mut = {}) => ({ lockingBytecode: fresh(lock), valueSatoshis: 1000n, token: { category: catU(), amount: 0n, nft: { capability: 'mutable', commitment: new Uint8Array(0) } }, ...mut });

    const mkTx = (mut = {}) => {
        const outputs = mut.outputs ?? [
            blankAt(buyerLock),                                                           /* the blank follows the money */
            { lockingBytecode: fresh(opLock), valueSatoshis: PRICE, ...(mut.price ?? {}) },
            { lockingBytecode: fresh(buyerLock), valueSatoshis: 1000n, ...(mut.change ?? {}) },
        ];
        const inputs = [
            { outpointTransactionHash: new Uint8Array(32).fill(1), outpointIndex: 0, sequenceNumber: 0xffffffff, unlockingBytecode: new Uint8Array(0) },
            { outpointTransactionHash: new Uint8Array(32).fill(2), outpointIndex: 0, sequenceNumber: 0xffffffff, unlockingBytecode: new Uint8Array(0) },
            ...(mut.extraInputs ?? []),
        ];
        const tx = { version: 2, locktime: 0, inputs, outputs };
        const sources = [
            { ...blankAt(fresh(locking)), ...(mut.input0 ?? {}) },                         /* the machine's blank */
            { lockingBytecode: fresh(buyerLock), valueSatoshis: 100_000n, ...(mut.funding ?? {}) },
            ...(mut.extraSources ?? []),
        ];
        /* NO SIGNATURE: the vending input's unlocking is just the push-only redeem — the
           script is the authorization. */
        tx.inputs[0].unlockingBytecode = fresh(encodeDataPush(fresh(redeem)));
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
    console.log(`--- blank-vending suite (price ${PRICE} sats, category ${CATEGORY.slice(0, 8)}…) ---`);
    R.push(evalCase('control: buyer pays the exact price, blank follows the money', true, {}));
    console.log('--- rejections ---');
    R.push(evalCase('underpay (price − 1)', false, { price: { valueSatoshis: PRICE - 1n } }));
    R.push(evalCase('overpay (price + 1) — the price is EXACT', false, { price: { valueSatoshis: PRICE + 1n } }));
    R.push(evalCase('payment redirected to a foreign locking', false, { price: { lockingBytecode: fresh(foreignLock) } }));
    R.push(evalCase('payment output carries a token', false, { price: { token: { category: catU(), amount: 5n } } }));
    R.push(evalCase('blank delivered to a THIRD-PARTY locking (not the payer)', false, { outputs: [blankAt(fresh(foreignLock)), { lockingBytecode: fresh(opLock), valueSatoshis: PRICE }, { lockingBytecode: fresh(buyerLock), valueSatoshis: 1000n }] }));
    R.push(evalCase('blank pre-tagged (non-empty commitment)', false, { outputs: [blankAt(buyerLock, { token: { category: catU(), amount: 0n, nft: { capability: 'mutable', commitment: new Uint8Array(32).fill(3) } } }), { lockingBytecode: fresh(opLock), valueSatoshis: PRICE }, { lockingBytecode: fresh(buyerLock), valueSatoshis: 1000n }] }));
    R.push(evalCase('blank wrong capability (minting)', false, { outputs: [blankAt(buyerLock, { token: { category: catU(), amount: 0n, nft: { capability: 'minting', commitment: new Uint8Array(0) } } }), { lockingBytecode: fresh(opLock), valueSatoshis: PRICE }, { lockingBytecode: fresh(buyerLock), valueSatoshis: 1000n }] }));
    R.push(evalCase('blank wrong category (foreign)', false, { outputs: [blankAt(buyerLock, { token: { category: new Uint8Array(32).fill(9), amount: 0n, nft: { capability: 'mutable', commitment: new Uint8Array(0) } } }), { lockingBytecode: fresh(opLock), valueSatoshis: PRICE }, { lockingBytecode: fresh(buyerLock), valueSatoshis: 1000n }] }));
    R.push(evalCase('blank carries a fungible amount', false, { outputs: [blankAt(buyerLock, { token: { category: catU(), amount: 7n, nft: { capability: 'mutable', commitment: new Uint8Array(0) } } }), { lockingBytecode: fresh(opLock), valueSatoshis: PRICE }, { lockingBytecode: fresh(buyerLock), valueSatoshis: 1000n }] }));
    R.push(evalCase('float siphon: out0 value inflated (change shrunk)', false, { outputs: [blankAt(buyerLock, { valueSatoshis: 1001n }), { lockingBytecode: fresh(opLock), valueSatoshis: PRICE }, { lockingBytecode: fresh(buyerLock), valueSatoshis: 999n }] }));
    R.push(evalCase('float siphon: out0 value deflated (change inflated)', false, { outputs: [blankAt(buyerLock, { valueSatoshis: 999n }), { lockingBytecode: fresh(opLock), valueSatoshis: PRICE }, { lockingBytecode: fresh(buyerLock), valueSatoshis: 1001n }] }));
    R.push(evalCase('funding input carries a token', false, { funding: { token: { category: catU(), amount: 1n } } }));
    R.push(evalCase('foreign token at the vending locking (mutable FOREIGN NFT as in0)', false, { input0: { token: { category: new Uint8Array(32).fill(9), amount: 0n, nft: { capability: 'mutable', commitment: new Uint8Array(0) } } } }));
    R.push(evalCase('extra input (3 total)', false, { extraInputs: [{ outpointTransactionHash: new Uint8Array(32).fill(3), outpointIndex: 0, sequenceNumber: 0xffffffff, unlockingBytecode: new Uint8Array(0) }], extraSources: [{ lockingBytecode: fresh(buyerLock), valueSatoshis: 1000n }] }));
    R.push(evalCase('shape: only 2 outputs', false, { outputs: [blankAt(buyerLock), { lockingBytecode: fresh(opLock), valueSatoshis: PRICE }] }));
    R.push(evalCase('shape: 4 outputs', false, { outputs: [blankAt(buyerLock), { lockingBytecode: fresh(opLock), valueSatoshis: PRICE }, { lockingBytecode: fresh(buyerLock), valueSatoshis: 1000n }, { lockingBytecode: fresh(buyerLock), valueSatoshis: 546n }] }));
    R.push(evalCase('change output carries a token', false, { change: { token: { category: catU(), amount: 50n } } }));
    console.log(`\n${R.filter(Boolean).length}/${R.length} match expectation`);
    return R.every(Boolean);
}

if (process.argv[1]?.endsWith("blank-vending.mjs")) {
    const ok = await vendingSuite();
    process.exit(ok ? 0 : 1);
}
