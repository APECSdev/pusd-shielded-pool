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

/* carrier: OP_RETURN OP_PUSHDATA1 <169> <payload> (2-out) / <201> (3-out) */
export const CARRIER_LEN = 169;
export const CARRIER_LEN_3OUT = 201;
export const STATE_INDEX = 2;   // role 2's own input index, fixed by the role dispatch
const CARRIER_PREFIX = Buffer.from([0x6a, 0x4c, CARRIER_LEN]);
const CARRIER_PREFIX_3OUT = Buffer.from([0x6a, 0x4c, CARRIER_LEN_3OUT]);

/* the eight limbs, in the order the 2-out carrier stores them */
export const CARRIER_FIELDS = ['nf0', 'nf1', 'cm0', 'cm1', 'newRoot', 'pv', 'sign'];
export const CARRIER_FIELDS_3OUT = ['nf0', 'nf1', 'cm0', 'cm1', 'cm2', 'newRoot', 'pv', 'sign'];
export function carrierOf({ nf0, nf1, cm0, cm1, cm2, newRoot, pv, sign }, outs = 2) {
    const len = outs === 3 ? CARRIER_LEN_3OUT : CARRIER_LEN;
    const b = Buffer.alloc(len);
    const put = (v, off, l) => { let x = BigInt(v); for (let i = 0; i < l; i++) { b[off + i] = Number(x & 0xffn); x >>= 8n; } };
    put(nf0, 0, 32); put(nf1, 32, 32); put(cm0, 64, 32); put(cm1, 96, 32);
    if (outs === 3) {
        put(cm2, 128, 32); put(newRoot, 160, 32); put(pv, 192, 8); put(sign, 200, 1);
    } else {
        put(newRoot, 128, 32); put(pv, 160, 8); put(sign, 168, 1);
    }
    return b;
}
export const carrierOutput = (payload) => Buffer.from([0x6a, 0x4c, payload.length, ...payload]);

/* n1 = SHA256(preimage) with the top 3 bits of the big-endian digest cleared (the actionHash).
   2-out preimage: nf0|nf1|cm0|cm1|pvAbs|pvSign|assetCategory|newRoot        (256 bytes)
   3-out preimage: nf0|nf1|cm0|cm1|cm2|pvAbs|pvSign|assetCategory|newRoot    (288 bytes) */
export function actionHashOf({ nf0, nf1, cm0, cm1, cm2, pv, sign, categoryDisplay, newRoot }, outs = 2) {
    const be32 = (v) => { const b = Buffer.alloc(32); let x = BigInt(v); for (let i = 31; i >= 0 && x > 0n; i--) { b[i] = Number(x & 0xffn); x >>= 8n; } return b; };
    const pre = outs === 3
        ? Buffer.concat([be32(nf0), be32(nf1), be32(cm0), be32(cm1), be32(cm2), be32(pv), be32(sign), Buffer.from(categoryDisplay, 'hex'), be32(newRoot)])
        : Buffer.concat([be32(nf0), be32(nf1), be32(cm0), be32(cm1), be32(pv), be32(sign), Buffer.from(categoryDisplay, 'hex'), be32(newRoot)]);
    const h = Buffer.from(sha(pre));
    h[0] &= 0x1f;
    return BigInt('0x' + h.toString('hex'));
}

export function covenantParams({ categoryOnChain, assetCategoryOnChain = null }) {
    const catOn = Buffer.from(categoryOnChain, 'hex');       // on-chain (reversed) order, 32 B
    const assetOn = assetCategoryOnChain ? Buffer.from(assetCategoryOnChain, 'hex') : null;
    return {
        categoryOnChain: catOn,
        categoryDisplay: Buffer.from(catOn).reverse(),       // natural big-endian, for the preimage
        catMutable: Buffer.concat([catOn, Buffer.from([0x01])]),
        catBare: catOn,
        ...(assetOn ? {
            assetOnChain: assetOn,
            assetDisplay: Buffer.from(assetOn).reverse(),   // the PUSD category, display order
            assetBare: assetOn,                             // the bare-FT push (32-B reversed) — probe-verified
        } : {}),
    };
}

/* The v3 nullifier-set variant: pass v3 = { walkAHash, walkBHash } (the SHA256
   digests of the deployed walkA/walkB lockings — wip-role2-hook/walk-scripts.mjs).
   Changes vs the deployed hook (all v3-only; the 2-out/3-out paths stay
   byte-identical):
     - check 4w (NEW): inputs 3/4 are the nullifier-data inputs — their lockings
       are pinned by SHA256 hash (UTXOBYTECODE(3) == walkA, (4) == walkB as
       digests; the raw scripts are ~280 B, hashing keeps the hook small);
     - check 7 (the nullifier FOLD) is REMOVED — it was the broken mechanism
       (R2-NULLIFIER-DOUBLING): a fold cannot detect reuse. The SHA256 SMT
       verified by the walk scripts replaces it (walkA proves nf0's slot empty
       against the state's nullSetRoot and emits midRoot; walkB proves nf1's
       slot empty against midRoot and pins finalNullRoot into out1's commitment
       second half);
     - check 10: role 2 verifies the new state commitment's LENGTH (64) and its
       FIRST half (== the carrier's newRoot — the note root); the SECOND half
       (finalNullRoot) is pinned by walkB. Two scripts jointly pin the state.
   The carrier, the actionHash preimage (9 fields), nPublic 2: ALL UNCHANGED. */
export function covenantHook(P, outs = 2, v3 = null) {
    /*  holdings mode (the C architecture): pass v3.holdings = {} (truthy) with
        P.assetBare set (covenantParams({ …, assetCategoryOnChain })). The state
        commitment grows to 96 B — [noteRoot ‖ nullSetRoot ‖ balance32] — and the
        ASSET (e.g. real PUSD, a category we do NOT own) rides a dedicated holdings
        input (5) / deposit slot (6) pair, both locked to the H covenant (graph-pinned
        by hash, theft-guarded by its full-shape pins). out2 recreates the holdings at
        the same locking carrying exactly newBal; the unshield payout moves out2 → out3
        in the ASSET's bare category; out1 stays NFT-only (amount 0). The balance
        arithmetic is byte-identical — only its SOURCE moves: the authenticated third
        field of the state commitment, chained exactly like the note root (each hook run
        verifies out1[64..96) == to32LE(newBal)), so the holdings line is UNFORGEABLE —
        an action that does not carry the full committed balance dies on consensus
        token conservation. Absent v3.holdings, every byte below is the v3.1 build. */
    if (v3?.holdings && !P.assetBare) throw new Error('holdings mode requires covenantParams({ assetCategoryOnChain })');
    return (a) => {
        const H = v3?.holdings ?? null;
        /*  3-out variant: the carrier grows to 201 bytes (cm2) and the actionHash
            preimage grows to 288 bytes. The 2-out default is byte-identical to the
            deployed hook (regression: pool-hook.mjs must still build d71851a1…). */
        const CARRIER_LEN = outs === 3 ? CARRIER_LEN_3OUT : 169;
        const CARRIER_PREFIX = outs === 3 ? CARRIER_PREFIX_3OUT : Buffer.from([0x6a, 0x4c, 169]);
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

        /* ── 3. the carrier: output 0 is exactly OP_RETURN <169|201 bytes> ─── */
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

        /* ── 4. split the payload: nf0 nf1 cm0 cm1 [cm2] newRoot pv(8) sign(1) ─ */
        const take32 = (from, name) => {
            a.push(32).op(OP.SPLIT, 2, name, from);
        };
        take32('pl', 'nf0');
        take32('pl', 'nf1');
        take32('pl', 'cm0');
        take32('pl', 'cm1');
        if (outs === 3) take32('pl', 'cm2');
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

        /* ── 4w. (v3) the nullifier-data inputs' lockings are the walk scripts ── */
        if (v3) {
            /*  SHA256(UTXOBYTECODE(j)) == walkXHash for j = 3, 4  */
            for (const [j, h] of [[3, v3.walkAHash], [4, v3.walkBHash]]) {
                a.push(j).op(IX.UTXOBYTECODE, 1, 'wl' + j);
                a.pick('wl' + j).op(OP.SHA256, 1, 'wh' + j);
                a.pushBytes(h).op(OP.EQUALVERIFY, 2);
            }
            a.mark('p4w');
        }

        /* ── 5. n0 == the stored merkle root (active input's commitment[0..32)) ── */
        if (process.env.POOL_DEBUG) console.error('[hook] model stack top-> :', a.st.slice(-10).reverse().join(' | '));
        a.push(STATE_INDEX).op(IX.UTXOTOKCOMMIT, 1, 'com');
        a.pick('com').push(32).op(OP.SPLIT, 2, 'stored', 'oldNull');
        if (H) {
            /*  holdings: the commitment is 96 B — split the tail again:
                [nullSetRoot ‖ balance32]. bal rides the STACK into check 8 (the
                authenticated source — the UTXO's own FT is no longer the balance);
                the nullSetRoot half stays walkA's domain. UTXOTOKAMT on a tokenless
                UTXO pushes EMPTY (= 0) — probe-verified 2026-11-27. */
            a.pick('oldNull').push(32).op(OP.SPLIT, 2, 'nullTail', 'bal64').drop('nullTail');
            a.pick('bal64').op(OP.BIN2NUM, 1, 'bal');
            /*  defense in depth: in holdings mode the state NFT is NFT-ONLY */
            a.push(STATE_INDEX).op(IX.UTXOTOKAMT, 1, 'samt');
            a.pick('samt').push(0).op(OP.NUMEQUALVERIFY, 2);
        }
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
        rev('nf0'); rev('nf1'); rev('cm0'); rev('cm1');
        if (outs === 3) rev('cm2');
        rev('newRoot');
        /*  be32(x) = REVERSEBYTES(NUM2BIN(x, 32)) — pv and sign are small VM numbers  */
        const be32 = (name) => { a.pick(name).push(32).op(OP.NUM2BIN, 2, name + '_le').op(IX.REVERSEBYTES, 1, name + '_be'); };
        be32('pv'); be32('sign');
        /*  preimage = be(nf0) ‖ be(nf1) ‖ be(cm0) ‖ be(cm1) [‖ be(cm2)] ‖ be32(pv) ‖ be32(sign) ‖ cat ‖ be(newRoot)
            The category field is the CIRCUIT's witness category. v3.1: the pool's own
            (pool == asset by design). Holdings mode: the ASSET's display form — the
            circuit witness and every minted fixture/sweep proof bind the asset (the
            2026-11-27 whichcat probe: our-v3-proofs + our-v3-mpc-proofs both bind
            2469acc5…), so the hook MUST recompute with P.assetDisplay or honest
            actions die at check 6. Caught in review: V4H-PIVOT-NITO-REVIEW §1. */
        a.pick('nf0_be').pick('nf1_be').op(OP.CAT, 2, 'a1');
        a.pick('cm0_be').pick('cm1_be').op(OP.CAT, 2, 'a2');
        a.pick('pv_be').pick('sign_be').op(OP.CAT, 2, 'a3');
        a.pushBytes(H ? P.assetDisplay : P.categoryDisplay).pick('newRoot_be').op(OP.CAT, 2, 'a4');
        if (outs === 3) {
            a.pick('a2').pick('cm2_be').op(OP.CAT, 2, 'a2c');
            a.pick('a1').pick('a2c').op(OP.CAT, 2, 'b1');
        } else {
            a.pick('a1').pick('a2').op(OP.CAT, 2, 'b1');
        }
        a.pick('a3').pick('a4').op(OP.CAT, 2, 'b2');
        a.pick('b1').pick('b2').op(OP.CAT, 2, 'pre');
        /*  OP_SIZE again — same non-popping VM as check 3: pre stays, presz lands on top. */
        a.op(OP.SIZE, 1, 'pre', 'presz').push(outs === 3 ? 288 : 256).op(OP.NUMEQUALVERIFY, 2);
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
        /*  v3: REMOVED — the fold cannot stop a double-spend (R2-NULLIFIER-DOUBLING).
            The hook-level SMT (the walk scripts at inputs 3/4, pinned at 4w) replaces
            it: walkA emits midRoot from the state's nullSetRoot, walkB pins
            finalNullRoot into out1's commitment. In the non-v3 paths the fold stays
            exactly as deployed (regression: 2-out builds d71851a1…, 3-out 628207b1…). */
        if (!v3) {
            a.pick('oldNull').pick('nf0').op(OP.CAT, 2, 'n1a');
            a.pick('n1a').pick('nf1').op(OP.CAT, 2, 'n1b');
            a.pick('n1b').op(OP.SHA256, 1, 'newNull');
            a.mark('p7');
        } else {
            /* the state commitment's second half is the WALK's domain — drop the
               split tail so the exit-depth bookkeeping stays exact. In holdings mode
               the tail was consumed at check 5 (bal extracted; the rest is residue
               the D0 exit loop drops by position). */
            if (!H) a.drop('oldNull');
        }

        /* ── 8. newBalance == balance + pv - 2·sign·pv  (>= 0) ──────────────── */
        /*  holdings mode: 'bal' is already on the stack from the state commitment's
            third field (check 5) — the arithmetic below is byte-identical either way. */
        if (!H) a.push(STATE_INDEX).op(IX.UTXOTOKAMT, 1, 'bal');
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
        a.push(H ? 3 : 2).pick('sign').op(OP.ADD, 2, 'exp');
        a.pick('oc').pick('exp').op(OP.NUMEQUALVERIFY, 2);

        /* ── 9. out1 = the new state, locked back to P2SH32(R) ──────────────── */
        a.push(1).op(IX.OUTBYTECODE, 1, 'o1b');
        a.push(STATE_INDEX).op(IX.UTXOBYTECODE, 1, 'own');
        a.pick('o1b').pick('own').op(OP.EQUALVERIFY, 2);
        a.push(1).op(IX.OUTTOKCAT, 1, 'o1cat').pushBytes(P.catMutable).op(OP.EQUALVERIFY, 2);
        a.push(1).op(IX.OUTTOKCOMMIT, 1, 'o1com');
        if (!v3) {
            a.pick('newRoot').pick('newNull').op(OP.CAT, 2, 'newCom');
            a.pick('o1com').pick('newCom').op(OP.EQUALVERIFY, 2);
        } else {
            /*  v3: the commitment is noteRoot ‖ finalNullRoot. Role 2 pins the LENGTH
                and the FIRST half (== the carrier's newRoot); walkB pins the second
                half. OP_SIZE is non-popping: the operand returns under the size.
                Holdings mode: 96 B — [noteRoot ‖ finalNullRoot ‖ balance32] — and the
                third field must equal to32LE(newBal): the balance chain. */
            a.op(OP.SIZE, 1, 'o1com', 'csz').push(H ? 96 : 64).op(OP.NUMEQUALVERIFY, 2);
            a.push(32).op(OP.SPLIT, 2, 'onr', 'nullTail');
            a.pick('onr').pick('newRoot').op(OP.EQUALVERIFY, 2);
            if (H) {
                a.pick('nullTail').push(32).op(OP.SPLIT, 2, 'nullSet2', 'balTail').drop('nullSet2');
                a.pick('newBal').push(32).op(OP.NUM2BIN, 2, 'nb32');
                a.pick('balTail').pick('nb32').op(OP.EQUALVERIFY, 2);
            }
            a.drop('nullTail');
        }
        a.push(1).op(IX.OUTTOKAMT, 1, 'o1amt');
        if (H) a.pick('o1amt').push(0).op(OP.NUMEQUALVERIFY, 2);   /* the state is NFT-only */
        else a.pick('o1amt').pick('newBal').op(OP.NUMEQUALVERIFY, 2);
        a.mark('p9');

        /* ── 9h. (holdings) out2 = the new holdings UTXO ──────────────────── */
        /*  The ASSET's FT balance line: same locking as the current holdings input
            (the chain — genesis funds it at H, every action recreates it at out2),
            the asset's BARE category (the 32-B reversed push — probe-verified), and
            exactly newBal. Conservation across 5/6 → 2/(3) is enforced by consensus
            token rules; this pin is what makes the line unforgeable (see check 5). */
        if (H) {
            a.push(2).op(IX.OUTBYTECODE, 1, 'o2b');
            a.push(5).op(IX.UTXOBYTECODE, 1, 'h5own');
            a.pick('o2b').pick('h5own').op(OP.EQUALVERIFY, 2);
            a.push(2).op(IX.OUTTOKCAT, 1, 'o2cat').pushBytes(P.assetBare).op(OP.EQUALVERIFY, 2);
            a.push(2).op(IX.OUTTOKAMT, 1, 'o2amt');
            a.pick('o2amt').pick('newBal').op(OP.NUMEQUALVERIFY, 2);
            a.mark('p9h');
        }

        /* ── 10. unshield: the payout (out2; out3 in holdings mode) pays pv ──── */
        a.pick('sign').push(1).op(OP.NUMEQUAL, 2, 'un').op(OP.IF, 1);
        a.push(H ? 3 : 2).op(IX.OUTTOKCAT, 1, 'o2cat').pushBytes(H ? P.assetBare : P.catBare).op(OP.EQUALVERIFY, 2);
        a.push(H ? 3 : 2).op(IX.OUTTOKAMT, 1, 'o2amt').pick('pv').op(OP.NUMEQUALVERIFY, 2);
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
