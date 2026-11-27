pragma circom 2.1.6;
include "../node_modules/circomlib/circuits/mux1.circom";
template M1() { signal input c[2]; signal input s; signal output out; component m = Mux1(); m.c[0] <== c[0]; m.c[1] <== c[1]; m.s <== s; out <== m.out; }
component main {public [c, s]} = M1();
