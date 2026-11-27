pragma circom 2.1.6;
include "../node_modules/circomlib/circuits/sha256/sha256.circom";
template S() { signal input in[2816]; signal output out[256]; component h = Sha256(2816); for (var i = 0; i < 2816; i++) { h.in[i] <== in[i]; } out[0] <== h.out[0]; }
component main {public [in]} = S();
