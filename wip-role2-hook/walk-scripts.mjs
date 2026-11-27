// walk-scripts.mjs — the v3 hook-level nullifier-set WALK SCRIPTS (BCH-2026, raw lockings).
//
// The nullifier set is a SHA256 sparse Merkle tree of depth 254 keyed by the
// carrier's proof-bound nullifier slices (spike decision: docs/NULLIFIER-SET-
// SPIKE-2026-11-27.md — the in-circuit option was refused by the pot18 phase-1).
// Every pool action carries TWO dedicated nullifier-data inputs:
//
//   input 3 "walkA" — locked to script A (a RAW locking, not P2SH: the walk code
//     is the locking bytecode itself, so the ~8.2-KB sibling witness does not
//     also have to push a redeem script under the 10,000-B unlocking cap).
//   input 4 "walkB" — locked to script B.
//
// Both scripts run the SAME dual walk as the spike's probe (probe-walk-cost.mjs),
// in OP_BEGIN/UNTIL loop form (~0.5 KB of code vs the unrolled 11,656 B, which
// exceeded the 10,000-B locking cap at D=254):
//
//   OLD walk: fold the 32-zero-byte leaf up the 254 supplied siblings; the
//     result MUST equal the walk's anchor root — proving the slot addressed by
//     the key is EMPTY (non-membership: the nullifier is not yet spent).
//   NEW walk: fold the 32-B spent marker [1,0..] up the same siblings; the
//     result is the post-insert root, pinned as follows:
//
//   walkA (input 3): key    = carrier nf0 slice (OUTPUTBYTECODE(0) payload[0..32])
//                    anchor = the state NFT commitment's SECOND half
//                             (UTXOTOKENCOMMITMENT(2)[32..64] = nullSetRoot)
//                    emits  = midRoot, pinned to the 32-B item at the bottom of
//                             walkA's OWN unlocking (self-published datum)
//   walkB (input 4): key    = carrier nf1 slice (payload[32..64])
//                    anchor = midRoot, read from INPUTBYTECODE(3)'s first push
//                             (walkA's declared midRoot — same-tx atomicity
//                             makes the shared surface sound: walkA verified it)
//                    emits  = finalNullRoot, REQUIRED to equal the new state
//                             NFT commitment's second half
//                             (OUTPUTTOKENCOMMITMENT(1)[32..64])
//
// The role-2 hook pins walkA's and walkB's lockings (SHA256 hash compares) and
// checks the new state commitment's FIRST half (the note root); walkB pins the
// second half. The old fold check 7 is gone — the SMT replaces it.
//
// Soundness notes:
//   - the key bits are EXTRACTED IN SCRIPT from the carrier slice (byte i>>3,
//     mask 1<<(i&7), LSB-first — the probe's convention): the walked slot is
//     bound to the proof-bound nullifier, not chosen by the witness. Bits from
//     the witness would DECOUPLE the walked slot from the claimed nullifier and
//     re-open the replay.
//   - the sibling blob is length-pinned (8,128 B = 254×32) and consumed by a
//     counter-driven loop; a wrong-length or wrong-count walk cannot fold to
//     the 254-deep pinned roots anyway (SHA256 preimage) — the pins are
//     defense in depth.
//   - replay dies at the OLD walk (a spent slot folds the marker, not zeros);
//     nf0 == nf1 dies in-circuit AND at walkB (nf0's slot is filled in midRoot).
//
// The spike's landmines honored: OP_SIZE is NON-POPPING (modeled pop-1/push-2);
// OP_SPLIT leaves the RIGHT part on top; OP_AND needs equal-length operands
// (the mask is NUM2BIN'd to exactly 1 B); the leaf values are 32-B items (a 1-B
// empty item hashes differently); every opcode used here is in the deployed
// program's probe-verified set. Loop-body stack hygiene: the loop's entry
// layout must be CONSTANT, so every per-level mutable (curO/curN/bp/bix/n/
// blob) is CONSUMED and re-pushed each iteration (roll, never pick) — picks
// would leak duplicates and shift the layout; read-only items (key/anchor/
// target) are picked freely.
//
// Witness layouts (unlocking pushes, first push = deepest stack item):
//   walkA: [midRoot(32 B), sibBlob(8,128 B)]   (midRoot = the declared post-nf0 root)
//   walkB: [sibBlob(8,128 B)]

import { Asm, OP, pushData } from './asm.mjs';
import { createHash } from 'node:crypto';

/* BCH 2026 introspection opcodes not in asm.mjs's OP table (same set as pool-hook.mjs) */
const IX = {
    TXVERSION: 0xc2, INPUTINDEX: 0xc0, UTXOTOKCAT: 0xce, UTXOTOKCOMMIT: 0xcf,
    OUTBYTECODE: 0xcd, OUTTOKCOMMIT: 0xd2, INPUTBYTECODE: 0xca,
};

export const NULL_D = 254;
export const SIB_BLOB_LEN = NULL_D * 32;      // 8,128 B
const sha = (b) => createHash('sha256').update(Buffer.from(b)).digest();
export const EMPTY_NULL_ROOT = (() => { let z = Buffer.alloc(32); for (let i = 0; i < NULL_D; i++) z = sha(Buffer.concat([z, z])); return z; })();
export const SPENT_MARKER = Buffer.from([1, ...Array(31).fill(0)]);
/* the carrier: OP_RETURN OP_PUSHDATA1 <201> <payload> — the 3-out/v3 layout */
export const CARRIER_LEN = 201;
const CARRIER_PREFIX = Buffer.from([0x6a, 0x4c, CARRIER_LEN]);

/* the SMT fold (JS mirror — probe-walk-cost.mjs's exact convention) */
export const smtBitOf = (key, i) => (key[i >> 3] >> (i & 7)) & 1;
export function smtWalk(leaf, key, sibs) {
    let cur = Buffer.from(leaf);
    for (let i = 0; i < NULL_D; i++) {
        const bit = smtBitOf(key, i);
        const left = bit ? sibs[i] : cur;
        const right = bit ? cur : sibs[i];
        cur = sha(Buffer.concat([left, right]));
    }
    return cur;
}

/* ─── the shared walk core ────────────────────────────────────────────────
   Runs over the entry layout [anchor, target, key, curO, curN, bp, bix,
   kbNum, n, blob] — the caller has already produced:
     anchor (the OLD-walk required root), target (the NEW-walk required root),
     key (the 32-B carrier slice), and pushed curO (32 zero bytes), curN (the
   spent marker), bix (0). kbNum (the current key byte as a number), bp (the
   bit position 0..7) and n (the level counter) are produced here. The witness
   blob must be on the stack. */
function walkCore(a) {
    /* the blob length pin: 254 siblings exactly (defense in depth) */
    a.roll('blob').op(OP.SIZE, 1, 'blob', 'bsz').push(SIB_BLOB_LEN).op(OP.NUMEQUALVERIFY, 2);
    /* kbNum = BIN2NUM(key[0] ‖ 0x00) — the current key byte as an UNSIGNED VM
       number (0..255). Two measured VM landmines force the zero-pad: BIN2NUM of
       the bare sign byte [0x80] decodes as −0 = ZERO, and RSHIFTNUM truncates
       toward zero for negatives, flipping the bit parity of every byte >= 0x80.
       The pad makes the number positive, so the shift is exact and
       bit i = (kbNum >> (i&7)) mod 2 holds for every byte. */
    a.pick('key').push(1).op(OP.SPLIT, 2, 'kbB', 'krest').drop('krest');
    a.pushBytes(Buffer.from([0])).bin(OP.CAT).op(OP.BIN2NUM, 1, 'kbNum');
    /* the bit position + the level counter */
    a.push(0, 'bp');
    a.push(NULL_D, 'n');
    /* the loop's entry layout (blob on top: the SPLIT pops [blob, 32]) */
    a.arrange(['anchor', 'target', 'key', 'curO', 'curN', 'bp', 'bix', 'kbNum', 'n', 'blob']);

    a.loop((s) => {
        /* consume the next sibling (the FRONT of the blob — level 0 first) */
        s.push(32).op(OP.SPLIT, 2, 'sib', 'blob');          // (sib, blob') — blob' on top
        /* the key bit: (kbNum >> bp) mod 2 — sh is consumed by the MOD (no pick) */
        s.pick('kbNum').pick('bp').op(OP.RSHIFTNUM, 2, 'sh');
        s.push(2).bin(OP.MOD, 'm');
        /* the bit steers the child order — both walks share the same sibling
           (the first CAT consumes a COPY of sib, the second consumes sib) */
        s.ifElse(
            (t) => {   /* bit = 1: the sibling is the LEFT child */
                t.pick('sib', 'sibA').arrange(['sibA', 'curO']).bin(OP.CAT).op(OP.SHA256, 1, 'curO');
                t.arrange(['sib', 'curN']).bin(OP.CAT).op(OP.SHA256, 1, 'curN');
            },
            (e) => {   /* bit = 0: the current value is the LEFT child */
                e.pick('sib', 'sibA').arrange(['curO', 'sibA']).bin(OP.CAT).op(OP.SHA256, 1, 'curO');
                e.arrange(['curN', 'sib']).bin(OP.CAT).op(OP.SHA256, 1, 'curN');
            },
        );
        /* bit advance: bp+1, wrap at 8 -> bp=0, bix+1, kbNum = the next key byte */
        s.roll('bp').op(OP.ADD1, 1, 'bp');
        s.pick('bp').push(8).bin(OP.NUMEQUAL, 'wrap');
        s.ifElse(
            (t) => {   /* byte exhausted: bp=0, bix+1, kbNum = key[bix'] */
                t.drop('bp').push(0, 'bp');
                t.roll('bix').op(OP.ADD1, 1, 'bix');
                t.pick('key').pick('bix').op(OP.SPLIT, 2, 'kl', 'kr');
                /* the second SPLIT consumes kr + the pushed 1 */
                t.push(1).op(OP.SPLIT, 2, 'kbB2', 'krest2').drop('krest2').drop('kl');
                t.pushBytes(Buffer.from([0])).bin(OP.CAT).op(OP.BIN2NUM, 1, 'kbNum2');
                t.drop('kbNum').rename('kbNum2', 'kbNum');
            },
            (e) => {   /* same key byte continues */
            },
        );
        /* the counter + the UNTIL condition (exit when n reaches 0) */
        s.roll('n').op(OP.SUB1, 1, 'n');
        s.pick('n').push(0).bin(OP.NUMEQUAL, 'done');
    });

    /* epilogue: the two folds must equal the pinned roots (the arranges CONSUME
       curO/anchor and curN/target; the EQUALVERIFYs pop both sides) */
    a.arrange(['curO', 'anchor']).op(OP.EQUALVERIFY, 2);
    a.arrange(['curN', 'target']).op(OP.EQUALVERIFY, 2);
    /* clean stack: exactly [1] — key/bp/bix/kbNum/n/blob remain */
    for (const name of ['key', 'bp', 'bix', 'kbNum', 'n', 'blob']) a.drop(name);
    a.emit(OP.TRUE);
}

/* ─── walkA — input 3: walk nf0 from the state's nullSetRoot to midRoot ── */
export function buildWalkA(categoryOnChainHex, commit96 = false) {
    const catMutable = Buffer.concat([Buffer.from(categoryOnChainHex, 'hex'), Buffer.from([0x01])]);
    /* the witness items are already on the stack: [midRoot, blob] */
    const a = new Asm(['midRoot', 'blob']);
    a.op(IX.TXVERSION, 0, 'tv').push(2).op(OP.NUMEQUALVERIFY, 2);
    a.op(IX.INPUTINDEX, 0, 'ix').push(3).op(OP.NUMEQUALVERIFY, 2);
    /* input 2 is the pool's state NFT (the same pin as the hook's check 2) */
    a.push(2).op(IX.UTXOTOKCAT, 1, 'icat').pushBytes(catMutable).op(OP.EQUALVERIFY, 2);
    /* the carrier: output 0 is exactly OP_RETURN <201 bytes> (hook check 3's shape) */
    a.push(0).op(IX.OUTBYTECODE, 1, 'ob');
    a.op(OP.SIZE, 1, 'ob', 'osz').push(CARRIER_PREFIX.length + CARRIER_LEN).op(OP.NUMEQUALVERIFY, 2);
    a.push(CARRIER_PREFIX.length).op(OP.SPLIT, 2, 'opre', 'pl').roll('opre');
    a.pushBytes(CARRIER_PREFIX).op(OP.EQUALVERIFY, 2);
    a.push(32).op(OP.SPLIT, 2, 'key', 'plrest').drop('plrest');
    /* the anchor: the state commitment's second half = nullSetRoot */
    a.push(2).op(IX.UTXOTOKCOMMIT, 1, 'com');
    a.push(32).op(OP.SPLIT, 2, 'noteRoot', 'anchor').drop('noteRoot');
    /* commit96 (the holdings variant): the state commitment is 96 B —
       [noteRoot ‖ nullSetRoot ‖ balance32] — split off the balance tail so the
       walk folds against the 32-B nullSetRoot exactly as in the 64-B form. */
    if (commit96) a.push(32).op(OP.SPLIT, 2, 'anchor', 'anchorTail').drop('anchorTail');
    /* the walk accumulators (zeros32 = the empty slot; the marker = spent) */
    a.pushBytes(Buffer.alloc(32), 'curO');
    a.pushBytes(SPENT_MARKER, 'curN');
    a.push(0, 'bix');
    /* the target: midRoot — the witness item at the bottom of this unlocking */
    a.rename('midRoot', 'target');
    walkCore(a);
    return Uint8Array.from(a.code);
}

/* ─── walkB — input 4: walk nf1 from midRoot (walkA's published datum) ─── */
export function buildWalkB(categoryOnChainHex, commit96 = false) {
    const catMutable = Buffer.concat([Buffer.from(categoryOnChainHex, 'hex'), Buffer.from([0x01])]);
    const a = new Asm(['blob']);
    a.op(IX.TXVERSION, 0, 'tv').push(2).op(OP.NUMEQUALVERIFY, 2);
    a.op(IX.INPUTINDEX, 0, 'ix').push(4).op(OP.NUMEQUALVERIFY, 2);
    a.push(2).op(IX.UTXOTOKCAT, 1, 'icat').pushBytes(catMutable).op(OP.EQUALVERIFY, 2);
    a.push(0).op(IX.OUTBYTECODE, 1, 'ob');
    a.op(OP.SIZE, 1, 'ob', 'osz').push(CARRIER_PREFIX.length + CARRIER_LEN).op(OP.NUMEQUALVERIFY, 2);
    a.push(CARRIER_PREFIX.length).op(OP.SPLIT, 2, 'opre', 'pl').roll('opre');
    a.pushBytes(CARRIER_PREFIX).op(OP.EQUALVERIFY, 2);
    /* key = the carrier's nf1 slice: skip nf0 (32 B), take the next 32 B */
    a.push(32).op(OP.SPLIT, 2, 'nf0skip', 'pl2').drop('nf0skip');
    a.push(32).op(OP.SPLIT, 2, 'key', 'plrest').drop('plrest');
    /* the anchor: midRoot = the first push of walkA's unlocking (INPUTBYTECODE(3)):
       [0x20 ‖ midRoot ‖ 0x4d ‖ len ‖ blob] — skip the 1-B push prefix, take 32 B */
    a.push(3).op(IX.INPUTBYTECODE, 1, 'in3');
    a.push(1).op(OP.SPLIT, 2, 'j0', 'r0').drop('j0');
    a.push(32).op(OP.SPLIT, 2, 'anchor', 'r1').drop('r1');
    /* the walk accumulators */
    a.pushBytes(Buffer.alloc(32), 'curO');
    a.pushBytes(SPENT_MARKER, 'curN');
    a.push(0, 'bix');
    /* the target: out1's commitment second half = finalNullRoot */
    a.push(1).op(IX.OUTTOKCOMMIT, 1, 'o1c');
    a.push(32).op(OP.SPLIT, 2, 'nr1', 'target').drop('nr1');
    /* commit96 (the holdings variant): out1's commitment is 96 B — split off the
       balance tail (bytes 64..96) so the walk pins the 32-B finalNullRoot exactly. */
    if (commit96) a.push(32).op(OP.SPLIT, 2, 'target', 'targetTail').drop('targetTail');
    walkCore(a);
    return Uint8Array.from(a.code);
}

export function buildWalkScripts(categoryOnChainHex, opts = {}) {
    const walkA = buildWalkA(categoryOnChainHex, opts.commit96);
    const walkB = buildWalkB(categoryOnChainHex, opts.commit96);
    return {
        walkA, walkB,
        walkAHash: sha(walkA),
        walkBHash: sha(walkB),
        sizes: { walkA: walkA.length, walkB: walkB.length },
    };
}

/* ─── witness encodings ──────────────────────────────────────────────────── */
/* walkA unlocking: [midRoot(32) ‖ sibBlob(8,128)] — midRoot is the DECLARED
   post-nf0 root walkA computes (and pins to its own witness) and walkB reads
   back via INPUTBYTECODE(3). */
export const walkAWitness = (midRoot, sibs) =>
    Uint8Array.from([...pushData(midRoot), ...pushData(Buffer.concat(sibs))]);
/* walkB unlocking: [sibBlob] — the anchor comes from walkA's unlocking. */
export const walkBWitness = (sibs) =>
    Uint8Array.from([...pushData(Buffer.concat(sibs))]);
