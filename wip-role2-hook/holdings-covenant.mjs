// holdings-covenant.mjs — the H covenant: the ASSET-side theft guard (the C architecture).
//
// The holdings input (5) and the deposit slot (6) carry REAL third-party FT (e.g. PUSD —
// a category we do NOT own and can never mint) and hold NO witness. They are locked to
// P2SH32(H), where H pins the FULL 7-input action shape by locking-hash:
//     TXINPUTCOUNT == 7;
//     inputs 0/1/2  locked to the deployed PROGRAM (SHA256(UTXOBYTECODE) == progLockingHash);
//     inputs 3/4    locked to the walkA/walkB P2SH32 lockings (SHA256 == the walk hashes);
//     inputs 5/6    locked to H itself — the ACTIVE input's own UTXOBYTECODE IS P2SH32(H),
//                   so the sibling is pinned by plain byte-compare against it (the guard's
//                   self-pin trick; no bootstrap hash, no chicken-and-egg).
// A thief sweeping a holdings UTXO must assemble the full action shape; inputs 0/1/2 are
// then the deployed program, whose own validation (graph + hook + the Groth16 pairing)
// demands a real proof — the sweep dies at consensus. H adds no value rules: the balance
// accounting lives in the hook (check 5's third field + 9h), consensus token conservation
// closes the totals, and the hook's out2 pin makes the line unforgeable. Signature-free
// like the rest of the pool: every check is *VERIFY and pushes nothing; the final stack
// item is OP_1 (P2SH wants a truthy final — the minting-guard landmine, honored).
//
// Build per-deploy AFTER the program + walks (their lockings' hashes are inputs):
//   const H = buildHoldingsCovenant({ progLockingHashHex, walkAHashHex, walkBHashHex });
//   H.lockingHashHex — pass to the graph pin (POOL_HOLDINGS_HASH); record H.lockingHex in
//   the state file (the lock tool embeds it for the in5/in6 funding).
import { Asm, OP, pushData } from './asm.mjs';
import { createHash } from 'node:crypto';
import { p2sh32 } from './vm.mjs';

/* BCH 2026 introspection opcodes (same table convention as pool-hook.mjs) */
const IX = { INPUTINDEX: 0xc0, TXINPUTCOUNT: 0xc3, UTXOBYTECODE: 0xc7 };

export function buildHoldingsCovenant({ progLockingHashHex, walkAHashHex, walkBHashHex }) {
    const a = new Asm([]);
    a.op(IX.TXINPUTCOUNT, 0, 'n').push(7).op(OP.NUMEQUALVERIFY, 2);
    a.op(IX.INPUTINDEX, 0, 'ix');
    a.op(IX.UTXOBYTECODE, 1, 'mine');
    const pin = (j, hashHex) => {
        a.push(j).op(IX.UTXOBYTECODE, 1, 'u');
        a.pick('u').op(OP.SHA256, 1, 'uh');
        a.pushBytes(Buffer.from(hashHex, 'hex')).op(OP.EQUALVERIFY, 2);
        a.drop('u');
    };
    pin(0, progLockingHashHex); pin(1, progLockingHashHex); pin(2, progLockingHashHex);
    pin(3, walkAHashHex); pin(4, walkBHashHex);
    /* the sibling holdings input: the same H locking, by byte-compare vs the active's
       own. The sibling index is computed arithmetically — 11 − ix maps 5↔6 — because
       the Asm's IF/ELSE model double-counts branch pushes (both branches pushing the
       same-named item emit picks for a depth that never exists at runtime). */
    a.push(11).op(IX.INPUTINDEX, 0, 'ix2').op(OP.SUB, 2, 'oix');
    a.op(IX.UTXOBYTECODE, 1, 'other');
    a.pick('other').pick('mine').op(OP.EQUALVERIFY, 2);
    a.drop('other');
    a.drop('mine');
    /* truthy final (all checks are *VERIFY and push nothing) */
    a.push(1);
    const script = Uint8Array.from(a.code);
    const locking = p2sh32(script);
    return {
        script,
        redeemBytes: script.length,
        locking,
        lockingHex: Buffer.from(locking).toString('hex'),
        lockingHashHex: createHash('sha256').update(Buffer.from(locking)).digest('hex'),
    };
}
