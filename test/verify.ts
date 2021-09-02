const snarkjs = require("snarkjs");
import * as fs from 'fs';
import { genIdentity, Identity } from 'semaphore-identity-lib';
import { genExternalNullifier, genSignalHash, createTree, genIdentityCommitment_poseidon, genNullifierHash_poseidon } from 'semaphore-lib';
import * as ethers from 'ethers';

const ZERO_VALUE = BigInt(ethers.utils.solidityKeccak256(['bytes'], [ethers.utils.toUtf8Bytes('Semaphore')]));

async function run() {
    const n_levels = 20;
    const externalNullifier = genExternalNullifier('fast-sempahore-demo');
    const signalHash = genSignalHash('hello fast semaphore');
    const identity: Identity = genIdentity();
    const idCom = genIdentityCommitment_poseidon(identity);

    
    const tree = createTree(20, ZERO_VALUE, 5);
    tree.insert(idCom);
    const merkleeProof = tree.genMerklePath(0);
    // console.log(tree.zeros.length)

    const nullifierHash = genNullifierHash_poseidon(externalNullifier, identity.identityNullifier, n_levels);
    const { proof } = await snarkjs.groth16.fullProve(
    {
        signal_hash: signalHash,
        external_nullifier: externalNullifier,
        identity_path_index: merkleeProof.indices,
        path_elements: merkleeProof.pathElements,
        identity_pk: identity.keypair.pubKey,
        identity_nullifier: identity.identityNullifier,
        identity_trapdoor: identity.identityTrapdoor
    }
    , "./zkeyFiles/semaphore.wasm", "./zkeyFiles/semaphore_final.zkey");

    const pubSignals = [tree.root, nullifierHash, signalHash, externalNullifier];

    const vKey = JSON.parse(fs.readFileSync("./zkeyFiles/verification_key.json", 'utf-8'));
    const res = await snarkjs.groth16.verify(vKey, pubSignals, proof);

    if (res === true) {
        console.log("Verification OK");
    } else {
        console.log("Invalid proof");
    }
}

run().then(() => {
    process.exit(0);
});