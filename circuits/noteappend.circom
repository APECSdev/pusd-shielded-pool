// circuits/noteappend.circom
//
// PUSD shielded pool v3 — the note-tree APPEND proof (closes R3-FREE-NEWROOT).
//
// FINDING (measured 2026-11-27, spike-nullset/probe-freeroot-drain.mjs): in every
// prior circuit generation `newMerkleRoot` was a FREE witness input — bound into the
// actionHash but never constrained to a correct tree append. Two valid Groth16 proofs
// drain a pool: action A "plants" the root of a fake tree (one that contains a
// fabricated note of value = the pool balance); action B "spends" that fabricated
// note with membership proofs against the planted root. Both verified against the
// deployed 3-out VK (evidence: /home/apecs/cov/role2-probe-freeroot-drain-3out.json).
//
// THE FIX: the circuit now VERIFIES the append. Each action must prove that
// newMerkleRoot equals the old public root (merkleRoot, anchored on-chain by hook
// check 5) with this action's three output commitments appended at the tree's
// FRONTIER — three sequential DenseAppend inserts, each a dual walk:
//
//   OLD walk (leaf = 0, the tree's zero leaf): folds the zero leaf up the supplied
//     siblings and must land exactly on oldRoot — proving the target slot is EMPTY
//     and the siblings are the slot's true off-path subtrees (non-membership).
//   NEW walk (leaf = the new commitment): recomputes the same spine with the leaf
//     set and emits the updated root.
//
// THE DENSE-SHAPE RULE (frontier pin): the zero-ladder comparison
//     IsEqual(siblings[i], zh[i]) === 1 - keyBits[i]
// forces every height-i sibling to be the EMPTY-subtree hash zh[i] exactly when
// bit i of the slot index is 0 (the slot sits in the LEFT half: everything to its
// right is empty) and a filled subtree otherwise (bit = 1: the left neighbor lies
// entirely below the fill count). Only the tree's true frontier slot satisfies
// this together with the old walk — a witness cannot plant holes (append at an
// empty slot beyond the frontier) without breaking the rule at the height where
// its left neighbor is still empty. Holes would fork every sequentially-scanning
// client (the nito.cash scan appends in action order), so the rule keeps the
// on-chain tree dense and client-reconstructible.
//
// The zh ladder is HARDCODED (20 Poseidon constants, regenerable + asserted by the
// witness tooling at runtime — role2-op-witness-v3.mjs asserts this exact ladder):
// computing it in-circuit would cost 20 extra Poseidon(2) per instance.
//
// Conventions match note.circom's MerkleProof and the witness generator:
//   keyBits LSB-first (bit i steers level i), Poseidon(left, right) node hash,
//   zero leaf = 0, zh[i+1] = Poseidon(zh[i], zh[i]).

pragma circom 2.1.6;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/mux1.circom";
include "../node_modules/circomlib/circuits/comparators.circom";

/* The depth-20 Poseidon zero ladder (zh[0] = 0). Verified against the deployed
   genesis root convention (merkle.js zeroHashes / role2 witness zeros[]). */
template ZeroLadder20() {
    signal output zh[21];
    zh[0] <== 0;
    zh[1] <== 14744269619966411208579211824598458697587494354926760081771325075741142829156;
    zh[2] <== 7423237065226347324353380772367382631490014989348495481811164164159255474657;
    zh[3] <== 11286972368698509976183087595462810875513684078608517520839298933882497716792;
    zh[4] <== 3607627140608796879659380071776844901612302623152076817094415224584923813162;
    zh[5] <== 19712377064642672829441595136074946683621277828620209496774504837737984048981;
    zh[6] <== 20775607673010627194014556968476266066927294572720319469184847051418138353016;
    zh[7] <== 3396914609616007258851405644437304192397291162432396347162513310381425243293;
    zh[8] <== 21551820661461729022865262380882070649935529853313286572328683688269863701601;
    zh[9] <== 6573136701248752079028194407151022595060682063033565181951145966236778420039;
    zh[10] <== 12413880268183407374852357075976609371175688755676981206018884971008854919922;
    zh[11] <== 14271763308400718165336499097156975241954733520325982997864342600795471836726;
    zh[12] <== 20066985985293572387227381049700832219069292839614107140851619262827735677018;
    zh[13] <== 9394776414966240069580838672673694685292165040808226440647796406499139370960;
    zh[14] <== 11331146992410411304059858900317123658895005918277453009197229807340014528524;
    zh[15] <== 15819538789928229930262697811477882737253464456578333862691129291651619515538;
    zh[16] <== 19217088683336594659449020493828377907203207941212636669271704950158751593251;
    zh[17] <== 21035245323335827719745544373081896983162834604456827698288649288827293579666;
    zh[18] <== 6939770416153240137322503476966641397417391950902474480970945462551409848591;
    zh[19] <== 10941962436777715901943463195175331263348098796018438960955633645115732864202;
    zh[20] <== 15019797232609675441998260052101280400536945603062888308240081994073687793470;
}

/* DenseAppend(D): one dual-walk insert of `leaf` at the frontier slot addressed by
   keyBits (D bits, LSB-first, boolean-constrained by the caller), against the tree
   committed by oldRoot. Emits newRoot. The dense-shape rule pins the frontier. */
template DenseAppend(D) {
    signal input oldRoot;
    signal input leaf;
    signal input keyBits[D];
    signal input siblings[D];
    signal input zh[D + 1];
    signal output newRoot;

    signal oldCur[D + 1];
    signal newCur[D + 1];
    oldCur[0] <== 0;          // the OLD walk starts at the zero leaf (the slot's current content)
    newCur[0] <== leaf;        // the NEW walk starts at the appended commitment

    component oldMux[D];
    component newMux[D];
    component oldH[D];
    component newH[D];
    component shape[D];        // the dense-shape rule per level

    for (var i = 0; i < D; i++) {
        // old walk (same one-Mux1 sum trick as note.circom's MerkleProof)
        oldMux[i] = Mux1();
        oldMux[i].c[0] <== oldCur[i];      // bit=0 -> child is LEFT
        oldMux[i].c[1] <== siblings[i];    // bit=1 -> sibling is LEFT
        oldMux[i].s <== keyBits[i];
        oldH[i] = Poseidon(2);
        oldH[i].inputs[0] <== oldMux[i].out;
        oldH[i].inputs[1] <== oldCur[i] + siblings[i] - oldMux[i].out;
        oldCur[i + 1] <== oldH[i].out;

        // new walk (same spine, leaf set)
        newMux[i] = Mux1();
        newMux[i].c[0] <== newCur[i];
        newMux[i].c[1] <== siblings[i];
        newMux[i].s <== keyBits[i];
        newH[i] = Poseidon(2);
        newH[i].inputs[0] <== newMux[i].out;
        newH[i].inputs[1] <== newCur[i] + siblings[i] - newMux[i].out;
        newCur[i + 1] <== newH[i].out;

        // dense-shape rule: sibling == zh[i]  <=>  bit == 0
        shape[i] = IsEqual();
        shape[i].in[0] <== siblings[i];
        shape[i].in[1] <== zh[i];
        shape[i].out === 1 - keyBits[i];
    }

    oldCur[D] === oldRoot;     // non-membership: the zero leaf folds to the stored root
    newRoot <== newCur[D];
}
