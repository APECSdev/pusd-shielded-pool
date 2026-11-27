// smt_insert.circom — SPIKE (nullifier-set depth measurement, 2026-11-26).
//
// SMTInsert(D): collision-free sparse-Merkle-tree INSERT of the spent marker
// (leaf value 1) at the slot addressed by keyBits (D bits, LSB-first: bit i
// steers step i, the level from height i to height i+1). Dual-walk
// construction, sharing ONE siblings[] witness for both walks:
//
//   OLD walk (leaf = 0): proves the slot is EMPTY in the tree committed by
//     oldRoot — the non-membership proof (a walk from the zero leaf up the
//     supplied siblings must land exactly on oldRoot).
//   NEW walk (leaf = 1): recomputes the same spine with the leaf set and
//     emits newRoot.
//
// The on-path child vs sibling ordering per level uses the same one-Mux1
// sum trick as the note-tree MerkleProof (left+right = child+sibling, so the
// second side needs no second mux). Siblings are the TRUE off-path child node
// values at each height; on an empty spine these are the zero-hash ladder
// values (zh[0]=0, zh[i]=H(zh[i-1],zh[i-1])), so an empty tree has root
// zh[D] and the construction is witness-generatable for the genesis case.
//
// Both walks hash unconditionally (no found-level state machine): worst case
// is 2*Poseidon(2) per level per insert — the cost this spike measures.

pragma circom 2.1.6;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/mux1.circom";

template SMTInsert(D) {
    signal input oldRoot;
    signal input keyBits[D];      // LSB-first key bits (boolean-constrained upstream)
    signal input siblings[D];    // sibling[i] = off-path child node value at height i
    signal output newRoot;

    signal oldCur[D + 1];
    signal newCur[D + 1];
    oldCur[0] <== 0;
    newCur[0] <== 1;

    component oldMux[D];
    component newMux[D];
    component oldH[D];
    component newH[D];

    for (var i = 0; i < D; i++) {
        // old walk
        oldMux[i] = Mux1();
        oldMux[i].c[0] <== oldCur[i];      // bit=0 -> child is LEFT
        oldMux[i].c[1] <== siblings[i];    // bit=1 -> sibling is LEFT
        oldMux[i].s <== keyBits[i];

        oldH[i] = Poseidon(2);
        oldH[i].inputs[0] <== oldMux[i].out;
        oldH[i].inputs[1] <== oldCur[i] + siblings[i] - oldMux[i].out;
        oldCur[i + 1] <== oldH[i].out;

        // new walk (same spine, leaf = 1)
        newMux[i] = Mux1();
        newMux[i].c[0] <== newCur[i];
        newMux[i].c[1] <== siblings[i];
        newMux[i].s <== keyBits[i];

        newH[i] = Poseidon(2);
        newH[i].inputs[0] <== newMux[i].out;
        newH[i].inputs[1] <== newCur[i] + siblings[i] - newMux[i].out;
        newCur[i + 1] <== newH[i].out;
    }

    oldCur[D] === oldRoot;
    newRoot <== newCur[D];
}
