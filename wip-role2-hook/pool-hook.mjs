// pool-hook.mjs — the shielded pool's application rules as a bn-native-sound role-2 COVENANT hook.
//
// Follows chunked/bn254/real-keys/covenant.mjs (the SP1 / RISC Zero worked example).
// Registered with setCovenant() from ./script.mjs; runs inside role 2 right after STMT is
// decoded and range-checked, with n0 and n1 on the stack as named items.
//
// WHY A HOOK AND NOT A SIBLING COVENANT
//   The sound verifier's graph pins TXINPUTCOUNT == 3 and UTXOBYTECODE(j) == own for every j,
//   and the red team rejects a foreign-locking sibling even when it carries the honest pushes
//   (151 runs / 0 accepted). The covenant cannot sit beside it. The pool rules therefore move
//   INTO role 2 — the integration the artifact documents ("applications that release funds add
//   output rules in role 2").
//
// WHERE THE DATA COMES FROM
//   The prover may write anything into n0/n1. The pool must DERIVE them and require equality:
//     n0  = the pool's stored merkle root, read from the ACTIVE INPUT's NFT commitment
//           (role 2's own input is the pool's state carrier).
//     n1  = SHA256(nf0‖nf1‖cm0‖cm1‖be32(pv)‖be32(sign)‖category‖newRoot) with the top 3 bits
//           cleared, i.e. exactly the actionHash asset-pool.cash recomputed.
//   The eight transition limbs are carried by the transaction in output 0's OP_RETURN, the same
//   way SP1's public values are. That carrier is a convenience, NOT a trust anchor: the prover
//   cannot change it without changing n1, and n1 is bound to the proof by the GT-GLS fold role 2
//   already enforces. The anchor is that existing binding.
//
// OUTPUT SHAPE (outputs are otherwise unconstrained; these are the pool's rules)
//   out0  OP_RETURN <169-byte carrier>   nf0‖nf1‖cm0‖cm1‖newRoot‖pv(8B LE)‖sign(1B)
//   out1  new state, locked to P2SH32(R)  category+0x01, commitment = newRoot‖newNull, amount = newBalance
//   out2  (unshield only) public payout   bare category, amount = pv
import assert from 'node:assert/strict';
import { OP } from './asm.mjs';
import { sha } from './protocol.mjs';

/* BCH 2026 introspection opcodes not in asm.mjs's OP table */
const IX = {
    TXVERSION: 0xc2, INPUTINDEX: 0xc0, TXOUTPUTCOUNT: 0xc4, UTXOBYTECODE: 0xc7,
    UTXOTOKCAT: 0xce, UTXOTOKCOMMIT: 0xcf, UTXOTOKAMT: 0xd0,
    OUTBYTECODE: 0xcd, OUTTOKCAT: 0xd1, OUTTOKCOMMIT: 0xd2, OUTTOKAMT: 0xd3,
    REVERSEBYTES: 0xbc,
};

/* carrier: OP_RETURN OP_PUSHDATA1 <169> <payload> */
export const CARRIER_LEN = 169;
export const STATE_INDEX = 2;   // role 2's own input index, fixed by the role dispatch
const CARRIER_PREFIX = Buffer.from([0x6a, 0x4c, CARRIER_LEN]);

/* the eight limbs, in the order the carrier stores them */
export const CARRIER_FIELDS = ['nf0', 'nf1', 'cm0', 'cm1', 'newRoot', 'pv', 'sign'];
export function carrierOf({ nf0, nf1, cm0, cm1, newRoot, pv, sign }) {
    const b = Buffer.alloc(CARRIER_LEN);
    const put = (v, off, len) => { let x = BigInt(v); for (let i = 0; i < len; i++) { b[off + i] = Number(x & 0xffn); x >>= 8n; } };
    put(nf0, 0, 32); put(nf1, 32, 32); put(cm0, 64, 32); put(cm1, 96, 32);
    put(newRoot, 128, 32); put(pv, 160, 8); put(sign, 168, 1);
    return b;
}
export const carrierOutput = (payload) => Buffer.from([0x6a, 0x4c, payload.length, ...payload]);

/* n1 = SHA256(preimage) with the top 3 bits of the big-endian digest cleared (the actionHash) */
export function actionHashOf({ nf0, nf1, cm0, cm1, pv, sign, categoryDisplay, newRoot }) {
    const be32 = (v) => { const b = Buffer.alloc(32); let x = BigInt(v); for (let i = 31; i >= 0 && x > 0n; i--) { b[i] = Number(x & 0xffn); x >>= 8n; } return b; };
    const pre = Buffer.concat([be32(nf0), be32(nf1), be32(cm0), be32(cm1), be32(pv), be32(sign), Buffer.from(categoryDisplay, 'hex'), be32(newRoot)]);
    const h = Buffer.from(sha(pre));
    h[0] &= 0x1f;
    return BigInt('0x' + h.toString('hex'));
}

export function covenantParams({ categoryOnChain }) {
    const catOn = Buffer.from(categoryOnChain, 'hex');       // on-chain (reversed) order, 32 B
    return {
        categoryOnChain: catOn,
        categoryDisplay: Buffer.from(catOn).reverse(),       // natural big-endian, for the preimage
        catMutable: Buffer.concat([catOn, Buffer.from([0x01])]),
        catBare: catOn,
    };
}

export function covenantHook(P) {
    return (a) => {
        /*  Capture the two public inputs FIRST, before this hook pushes anything. n0 and n1 sit
            deep in role 2's stack (below the STMT scalars), so picking them later — after the
            carrier splits have pushed a dozen items — computes a depth that no longer matches the
            runtime stack. Copy them now and use the copies throughout. */
        a.pick('n0', 'k0');
        a.pick('n1', 'k1');
        const D0 = a.st.length;   /* everything above this at exit is ours to drop */

        /* ── 1. tx.version == 2 ─────────────────────────────────────────────── */
        a.op(IX.TXVERSION, 0, 'tv').push(2).op(OP.NUMEQUALVERIFY, 2);
        a.mark('p1');

        /* ── 2. the ACTIVE input carries the pool category as a MUTABLE NFT ─── */
        /*  role 2 is ALWAYS tx input 2 (the role dispatch is OP_INPUTINDEX + ROLE_ID), so the
            state index is a compile-time constant. Using a literal instead of OP_INPUTINDEX keeps
            the state input addressable without depending on the symbolic stack depth. */
        a.push(STATE_INDEX).op(IX.UTXOTOKCAT, 1, 'icat');
        a.pushBytes(P.catMutable).op(OP.EQUALVERIFY, 2);
        a.mark('p2');

        /* ── 3. the carrier: output 0 is exactly OP_RETURN <169 bytes> ──────── */
        a.push(0).op(IX.OUTBYTECODE, 1, 'ob');
        /*  OP_SIZE on the BCH-2026 VM is NON-POPPING: it leaves the operand and pushes its size.
            Model it exactly as the stock FILL local function does (script.mjs:75): pop 1, push 2
            (the operand returns to the stack under the size). A pop-1/push-1 model leaves the
            operand copy on the runtime stack and shifts every later pick by one — the exact bug
            this note replaces. */
        a.op(OP.SIZE, 1, 'ob', 'osz').push(CARRIER_PREFIX.length + CARRIER_LEN).op(OP.NUMEQUALVERIFY, 2);
        a.push(CARRIER_PREFIX.length).op(OP.SPLIT, 2, 'opre', 'pl').roll('opre');
        a.pushBytes(CARRIER_PREFIX).op(OP.EQUALVERIFY, 2);
        a.mark('p3');

        /* ── 4. split the payload: nf0 nf1 cm0 cm1 newRoot pv(8) sign(1) ───── */
        const take32 = (from, name) => {
            a.push(32).op(OP.SPLIT, 2, name, from);
        };
        take32('pl', 'nf0');
        take32('pl', 'nf1');
        take32('pl', 'cm0');
        take32('pl', 'cm1');
        take32('pl', 'newRoot');
        a.push(8).op(OP.SPLIT, 2, 'pv8', 'pl');
        a.rename('pl', 'sign1');
        a.roll('pv8').op(OP.BIN2NUM, 1, 'pv');
        a.roll('sign1').op(OP.BIN2NUM, 1, 'sign');
        /* sign ∈ {0,1} */
        a.pick('sign').push(0).op(OP.GREATERTHANOREQUAL, 2, 's0').op(OP.VERIFY, 1);
        a.pick('sign').push(1).op(OP.LESSTHANOREQUAL, 2, 's1').op(OP.VERIFY, 1);
        a.mark('p4');

        /* ── 4c. both fuel inputs carry the pool category as MUTABLE NFTs ──── */
        /*  Deposit tagging: the lock tx tags every fuel/deposit UTXO with an NFT whose
            commitment is SHA256(nf0 ‖ nf1) — the intended action's nullifiers — so standing
            fuel cannot be consumed by any other action. This recreates, as a commitment,
            the author binding the old pools got from their signed funding input. Inputs 0
            and 1 are the fuel/deposit pair (in0 carries the FT deposit on a shield); the
            tag NFTs are burned by the action — burn-by-omission is consensus-legal, the
            same rule that let the deploy destroy the minting NFT. */
        for (const j of [0, 1]) {
            a.push(j).op(IX.UTXOTOKCAT, 1, 'fcat' + j);
            a.pushBytes(P.catMutable).op(OP.EQUALVERIFY, 2);
        }
        a.mark('p4c');

        /* ── 4g. both fuel commitments == SHA256(nf0 ‖ nf1) (the deposit tag) ─ */
        /*  RAW LE limbs and the same SHA256 fold as check 7's nullifier hash: the tag is
            literally SHA256(carrier[0..64]). The lock builder computes the identical digest
            off-chain (pool-tx.mjs poolScenario) and stores it as each fuel output's NFT
            commitment. An attacker holding a valid proof of their own cannot match a tag
            locked for someone else's nullifiers — producing those nullifiers requires the
            victim's note keys. */
        a.pick('nf0').pick('nf1').op(OP.CAT, 2, 'tagPre');
        a.pick('tagPre').op(OP.SHA256, 1, 'tag');
        for (const j of [0, 1]) {
            a.push(j).op(IX.UTXOTOKCOMMIT, 1, 'fcom' + j);
            a.pick('fcom' + j).pick('tag').op(OP.EQUALVERIFY, 2);
        }
        a.mark('p4g');

        /* ── 5. n0 == the stored merkle root (active input's commitment[0..32)) ── */
        if (process.env.POOL_DEBUG) console.error('[hook] model stack top-> :', a.st.slice(-10).reverse().join(' | '));
        a.push(STATE_INDEX).op(IX.UTXOTOKCOMMIT, 1, 'com');
        a.pick('com').push(32).op(OP.SPLIT, 2, 'stored', 'oldNull');
        /*  byte comparison, not numeric: a 32-byte push decodes as a NEGATIVE VM number when its
            top byte is >= 0x80, so NUMEQUAL would reject honest roots half the time. n0 is a
            number here, so render it to its canonical 32-byte LE form first. */
        a.pick('k0').push(32).op(OP.NUM2BIN, 2, 'n0le');
        a.pick('stored').pick('n0le').op(OP.EQUALVERIFY, 2);
        a.mark('p5');

        /* ── 6. n1 == actionHash(nf0,nf1,cm0,cm1,pv,sign,category,newRoot) ───── */
        /*  The carrier limbs are the 32-byte LE VM-number forms (asset-pool.cash's
            covenant-arg convention). The circuit's actionHash preimage uses 32-byte
            BIG-ENDIAN fields, so every limb is REVERSEBYTES'd first — exactly what the
            deployed covenant does (asset-pool.cash lines 192-200: nf0.reverse() …
            newMerkleRoot.reverse()). The nullifier fold in check 7 below stays on the
            RAW forms — the deployed covenant folds `old + nf0 + nf1` without reversal. */
        const rev = (name) => { a.pick(name).op(IX.REVERSEBYTES, 1, name + '_be'); };
        rev('nf0'); rev('nf1'); rev('cm0'); rev('cm1'); rev('newRoot');
        /*  be32(x) = REVERSEBYTES(NUM2BIN(x, 32)) — pv and sign are small VM numbers  */
        const be32 = (name) => { a.pick(name).push(32).op(OP.NUM2BIN, 2, name + '_le').op(IX.REVERSEBYTES, 1, name + '_be'); };
        be32('pv'); be32('sign');
        /*  preimage = be(nf0) ‖ be(nf1) ‖ be(cm0) ‖ be(cm1) ‖ be32(pv) ‖ be32(sign) ‖ cat ‖ be(newRoot)  */
        a.pick('nf0_be').pick('nf1_be').op(OP.CAT, 2, 'a1');
        a.pick('cm0_be').pick('cm1_be').op(OP.CAT, 2, 'a2');
        a.pick('pv_be').pick('sign_be').op(OP.CAT, 2, 'a3');
        a.pushBytes(P.categoryDisplay).pick('newRoot_be').op(OP.CAT, 2, 'a4');
        a.pick('a1').pick('a2').op(OP.CAT, 2, 'b1');
        a.pick('a3').pick('a4').op(OP.CAT, 2, 'b2');
        a.pick('b1').pick('b2').op(OP.CAT, 2, 'pre');
        /*  OP_SIZE again — same non-popping VM as check 3: pre stays, presz lands on top. */
        a.op(OP.SIZE, 1, 'pre', 'presz').push(256).op(OP.NUMEQUALVERIFY, 2);
        /*  digest, clear the top 3 bits of the big-endian first byte, reverse to LE, compare */
        a.pick('pre').op(OP.SHA256, 1, 'h');
        a.pick('h').push(1).op(OP.SPLIT, 2, 'h0', 'hrest');
        a.roll('h0').pushBytes(Buffer.from([0x1f])).op(OP.AND, 2, 'hm');
        a.pick('hm').pick('hrest').op(OP.CAT, 2, 'hcat');
        a.pick('hcat').op(IX.REVERSEBYTES, 1, 'hle');
        a.pick('hle').op(OP.BIN2NUM, 1, 'dg');
        a.pick('dg').pick('k1').op(OP.NUMEQUALVERIFY, 2);
        a.mark('p6');

        /* ── 7. newNull == SHA256(oldNull ‖ nf0 ‖ nf1) ──────────────────────── */
        a.pick('oldNull').pick('nf0').op(OP.CAT, 2, 'n1a');
        a.pick('n1a').pick('nf1').op(OP.CAT, 2, 'n1b');
        a.pick('n1b').op(OP.SHA256, 1, 'newNull');
        a.mark('p7');

        /* ── 8. newBalance == balance + pv - 2·sign·pv  (>= 0) ──────────────── */
        a.push(STATE_INDEX).op(IX.UTXOTOKAMT, 1, 'bal');
        a.pick('bal').pick('pv').op(OP.ADD, 2, 'sum');
        a.pick('sign').pick('pv').op(OP.MUL, 2, 'spv');
        a.pick('spv').push(2).op(OP.MUL, 2, 'spv2');
        a.pick('sum').pick('spv2').op(OP.SUB, 2, 'newBal');
        a.pick('newBal').push(0).op(OP.GREATERTHANOREQUAL, 2, 'nb0').op(OP.VERIFY, 1);
        a.mark('p8');

        /* ── 8b. TXOUTPUTCOUNT == 2 + sign ───────────────────────────────────── */
        /*  Pin the transaction shape: exactly out0 (carrier), out1 (state), and for an
            unshield out2 (payout). Without this, a sign=0 transition could append an
            unchecked extra output. Consensus token conservation already limits totals;
            this is defense in depth and makes the payout rules total. */
        a.op(IX.TXOUTPUTCOUNT, 0, 'oc');
        a.push(2).pick('sign').op(OP.ADD, 2, 'exp');
        a.pick('oc').pick('exp').op(OP.NUMEQUALVERIFY, 2);

        /* ── 9. out1 = the new state, locked back to P2SH32(R) ──────────────── */
        a.push(1).op(IX.OUTBYTECODE, 1, 'o1b');
        a.push(STATE_INDEX).op(IX.UTXOBYTECODE, 1, 'own');
        a.pick('o1b').pick('own').op(OP.EQUALVERIFY, 2);
        a.push(1).op(IX.OUTTOKCAT, 1, 'o1cat').pushBytes(P.catMutable).op(OP.EQUALVERIFY, 2);
        a.pick('newRoot').pick('newNull').op(OP.CAT, 2, 'newCom');
        a.push(1).op(IX.OUTTOKCOMMIT, 1, 'o1com');
        a.pick('o1com').pick('newCom').op(OP.EQUALVERIFY, 2);
        a.push(1).op(IX.OUTTOKAMT, 1, 'o1amt');
        a.pick('o1amt').pick('newBal').op(OP.NUMEQUALVERIFY, 2);
        a.mark('p9');

        /* ── 10. unshield: out2 pays pv in the bare category ───────────────── */
        a.pick('sign').push(1).op(OP.NUMEQUAL, 2, 'un').op(OP.IF, 1);
        a.push(2).op(IX.OUTTOKCAT, 1, 'o2cat').pushBytes(P.catBare).op(OP.EQUALVERIFY, 2);
        a.push(2).op(IX.OUTTOKAMT, 1, 'o2amt').pick('pv').op(OP.NUMEQUALVERIFY, 2);
        /*  o2cat / o2amt are consumed by their own VERIFY ops above, so nothing is left to drop
            here; the branch creates no residue. */
        a.op(OP.ENDIF, 0);
        a.mark('p10');

        a.mark('p11');

        /* ── 11. drop everything this hook created, restoring role 2's stack ── */
        /*  Drop by POSITION, not by name: pick() copies share their source's name, so a
            name-based list drops only the topmost duplicate and leaks the rest — the
            leaked copies were shifting every later pick by one. D0 was captured at hook
            entry; dropping the top item repeatedly is always a plain OP_DROP. */
        while (a.st.length > D0) a.drop(a.st[a.st.length - 1]);
    };
}
