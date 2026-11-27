pragma circom 2.1.6;
include "./note.circom";
template MK() { signal input leaf; signal input pe[20]; signal input pb[20]; signal output root; component m = MerkleProof(20); m.leaf <== leaf; for (var d = 0; d < 20; d++) { m.pathElements[d] <== pe[d]; m.pathBits[d] <== pb[d]; } root <== m.root; }
component main {public [leaf]} = MK();
