pragma circom 2.1.6;
include "../node_modules/circomlib/circuits/bitify.circom";
include "./smt_insert.circom";
template P() {
    signal input key; signal input oldRoot; signal input siblings[254]; signal output newRoot;
    component n = Num2Bits(254); n.in <== key;
    component s = SMTInsert(254);
    s.oldRoot <== oldRoot;
    for (var d = 0; d < 254; d++) { s.keyBits[d] <== n.out[d]; s.siblings[d] <== siblings[d]; }
    newRoot <== s.newRoot;
}
component main {public [oldRoot]} = P();
