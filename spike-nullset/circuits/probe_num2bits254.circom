pragma circom 2.1.6;
include "../node_modules/circomlib/circuits/bitify.circom";
template N() { signal input in; signal output out[254]; component n = Num2Bits(254); n.in <== in; out[0] <== n.out[0]; }
component main {public [in]} = N();
