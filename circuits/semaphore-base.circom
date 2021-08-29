include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/babyjub.circom";
include "./tree.circom";


template CalculateIdentityCommitment() {
    signal input identity_public_key_subgroup_element;
    signal input identity_nullifier;
    signal input identity_trapdoor;

    signal output out;

    component hasher = Poseidon(3);
    hasher.inputs[0] <== identity_public_key_subgroup_element;
    hasher.inputs[1] <== identity_nullifier;
    hasher.inputs[2] <== identity_trapdoor;
    out <== hasher.out;
}

template CalculateNullifierHash() {
    signal input external_nullifier;
    signal input identity_nullifier;
    signal input n_levels;

    signal output out;

    component hasher = Poseidon(3);
    hasher.inputs[0] <== external_nullifier;
    hasher.inputs[1] <== identity_nullifier;
    hasher.inputs[2] <== n_levels;
    out <== hasher.out;
}


template VerifyPkOnCurve() {
    signal input identity_pk[2];

    component verify_identity_pk_on_curve = BabyCheck();
    verify_identity_pk_on_curve.x <== identity_pk[0];
    verify_identity_pk_on_curve.y <== identity_pk[1];
}

template Pk2SubgroupElement() {
    signal input identity_pk[2];
    signal output out;

    component dbl1 = BabyDbl();
    dbl1.x <== identity_pk[0];
    dbl1.y <== identity_pk[1];
    component dbl2 = BabyDbl();
    dbl2.x <== dbl1.xout;
    dbl2.y <== dbl1.yout;
    component dbl3 = BabyDbl();
    dbl3.x <== dbl2.xout;
    dbl3.y <== dbl2.yout;

    out <== dbl3.xout;
}

// n_levels must be < 32
template Semaphore(n_levels) {

    var LEAVES_PER_NODE = 5;
    var LEAVES_PER_PATH_LEVEL = LEAVES_PER_NODE - 1;

    signal input signal_hash;
    signal input external_nullifier;

    signal private input identity_pk[2];
    signal private input identity_nullifier;
    signal private input identity_trapdoor;
    signal private input identity_path_index[n_levels];
    signal private input path_elements[n_levels][LEAVES_PER_PATH_LEVEL];

    signal output nullifierHash;
    signal output root;

    component verifyPkOnCurve = VerifyPkOnCurve();
    verifyPkOnCurve.identity_pk[0] <== identity_pk[0];
    verifyPkOnCurve.identity_pk[1] <== identity_pk[1];

    component pk2SubgroupElement = Pk2SubgroupElement();
    pk2SubgroupElement.identity_pk[0] <== identity_pk[0];
    pk2SubgroupElement.identity_pk[1] <== identity_pk[1];

    component identity_commitment = CalculateIdentityCommitment();
    identity_commitment.identity_public_key_subgroup_element <== pk2SubgroupElement.out;
    identity_commitment.identity_nullifier <== identity_nullifier;
    identity_commitment.identity_trapdoor <== identity_trapdoor;

    component calculateNullifierHash = CalculateNullifierHash();
    calculateNullifierHash.external_nullifier <== external_nullifier;
    calculateNullifierHash.identity_nullifier <== identity_nullifier;
    calculateNullifierHash.n_levels <== n_levels;

    var i;
    var j;
    component inclusionProof = QuinTreeInclusionProof(n_levels);
    inclusionProof.leaf <== identity_commitment.out;

    for (i = 0; i < n_levels; i++) {
      for (j = 0; j < LEAVES_PER_PATH_LEVEL; j++) {
        inclusionProof.path_elements[i][j] <== path_elements[i][j];
      }
      inclusionProof.path_index[i] <== identity_path_index[i];
    }

    root <== inclusionProof.root;

    // Dummy square to prevent tampering signalHash
    signal signal_hash_squared;
    signal_hash_squared <== signal_hash * signal_hash;

    nullifierHash <== calculateNullifierHash.out;
}
