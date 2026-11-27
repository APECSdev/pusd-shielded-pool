pragma circom 2.1.6;
include "../node_modules/circomlib/circuits/smt/smtprocessor.circom";
template P() {
    signal input key; signal input oldRoot; signal input siblings[254]; signal output newRoot;
    component s = SMTProcessor(254);
    s.oldRoot <== oldRoot;
    s.oldKey <== key; s.oldValue <== 0; s.isOld0 <== 1;
    s.newKey <== key; s.newValue <== 1;
    s.fnc[0] <== 1; s.fnc[1] <== 0;
    for (var d = 0; d < 254; d++) { s.siblings[d] <== siblings[d]; }
    newRoot <== s.newRoot;
}
component main {public [oldRoot]} = P();
