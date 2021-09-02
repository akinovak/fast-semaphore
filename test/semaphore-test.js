const poseidonGenContract = require('circomlib/src/poseidon_gencontract.js');
const path = require('path');
const fs = require('fs');
const Web3 = require('web3');

const ZERO_VALUE = BigInt(ethers.utils.solidityKeccak256(['bytes'], [ethers.utils.toUtf8Bytes('Semaphore')]));

const { genExternalNullifier, genIdentity, genSignalHash, genIdentityCommitment, genProof_fastSemaphore, packToSolidityProof, genNullifierHash_poseidon, genIdentityCommitment_poseidon } = require('semaphore-lib');
const { expect } = require('chai');

describe("Semaphore", function () {
    it.skip("Should return the new semaphore", async function () {
      const PoseidonT3 = await ethers.getContractFactory(
          poseidonGenContract.generateABI(2),
          poseidonGenContract.createCode(2)
      )
      const poseidonT3 = await PoseidonT3.deploy();
      await poseidonT3.deployed();
  
  
      const PoseidonT6 = await ethers.getContractFactory(
          poseidonGenContract.generateABI(5),
          poseidonGenContract.createCode(5)
      );
      const poseidonT6 = await PoseidonT6.deploy();
      await poseidonT6.deployed();
  
      const Hasher = await ethers.getContractFactory("Hasher", {
          libraries: {
              PoseidonT3: poseidonT3.address,
              PoseidonT6: poseidonT6.address,
          },
        });
      const hasher = await Hasher.deploy();
      await hasher.deployed();

      const externalNullifier = genExternalNullifier("voting-1");

      const Semaphore = await ethers.getContractFactory("Semaphore", {
          libraries: {
              PoseidonT3: poseidonT3.address,
              PoseidonT6: poseidonT6.address,
          }
      });
      const semaphore = await Semaphore.deploy(20, externalNullifier);
      await semaphore.deployed();

      const leafIndex = 4;

      const idCommitments = [];

      for (let i=0; i<leafIndex;i++) {
        const tmpIdentity = genIdentity();
        const tmpCommitment = genIdentityCommitment(tmpIdentity);
        idCommitments.push(tmpCommitment);
      }

      const promises = idCommitments.map(async (id) => {
        const index = await semaphore.insertIdentity(id);
        return index;
      });

      await Promise.all(promises);


      const identity = genIdentity();
      let signal = 'yes';
      signal = Web3.utils.utf8ToHex(signal);
      const signalHash = genSignalHash(signal);
      const nullifiersHash = genNullifierHash_poseidon(externalNullifier, identity.identityNullifier, 20);
      const identityCommitment = genIdentityCommitment_poseidon(identity);

      await semaphore.insertIdentity(identityCommitment);

      const wasmFilePath =  path.join('./zkeyFiles', 'semaphore.wasm');
      const finalZkeyPath = path.join('./zkeyFiles', 'semaphore_final.zkey');

      idCommitments.push(identityCommitment);

      const witnessData = await genProof_fastSemaphore(identity, signalHash, 
        idCommitments, externalNullifier, 20, ZERO_VALUE, 5, wasmFilePath, finalZkeyPath);

      const { fullProof, root } = witnessData;
      const solidityProof = packToSolidityProof(fullProof);


      const packedProof = await semaphore.packProof(
        solidityProof.a, 
        solidityProof.b, 
        solidityProof.c,
      );


      const res = await semaphore.broadcastSignal(
            ethers.utils.hexlify(ethers.utils.toUtf8Bytes(signal)),
            packedProof,
            root,
            nullifiersHash,
            externalNullifier
      )

      expect(res.hash).to.be.an('string');

      // console.log(res);
    // const res = await semaphore.preBroadcastCheck(
    //     ethers.utils.hexlify(ethers.utils.toUtf8Bytes(signal)),
    //     packedProof,
    //     tree.root,
    //     nullifiersHash,
    //     signalHash,
    //     externalNullifier
    // )

    // console.log(res);

    // const res = await semaphore.verifyProof(
    //   solidityProof.a,
    //   solidityProof.b,
    //   solidityProof.c,
    //   solidityProof.inputs
    // );

    // console.log(solidityProof.inputs);
    // console.log(root, nullifiersHash, signalHash, externalNullifier)
    
    // console.log(res);
  
    });
  });