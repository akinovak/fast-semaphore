const poseidonGenContract = require("circomlib/src/poseidon_gencontract.js");
const path = require("path");
const fs = require("fs");
const Web3 = require("web3");
const snarkjs = require("snarkjs");

const ZERO_VALUE = BigInt(
  ethers.utils.solidityKeccak256(
    ["bytes"],
    [ethers.utils.toUtf8Bytes("Semaphore")]
  )
);

const {
  genExternalNullifier,
  genIdentity,
  genSignalHash,
  genIdentityCommitment,
  genProof_fastSemaphore,
  packToSolidityProof,
  genNullifierHash_poseidon,
  genIdentityCommitment_poseidon,
} = require("semaphore-lib");
const { expect } = require("chai");

describe("FastSemaphore", function () {
  it("Should return the new Fast Semaphore", async function () {
    const PoseidonT3 = await ethers.getContractFactory(
      poseidonGenContract.generateABI(2),
      poseidonGenContract.createCode(2)
    );
    const poseidonT3 = await PoseidonT3.deploy();
    await poseidonT3.deployed();

    const PoseidonT6 = await ethers.getContractFactory(
      poseidonGenContract.generateABI(5),
      poseidonGenContract.createCode(5)
    );
    const poseidonT6 = await PoseidonT6.deploy();
    await poseidonT6.deployed();

    //   const Hasher = await ethers.getContractFactory("Hasher", {
    //       libraries: {
    //           PoseidonT3: poseidonT3.address,
    //           PoseidonT6: poseidonT6.address,
    //       },
    //     });
    //   const hasher = await Hasher.deploy();
    //   await hasher.deployed();

    const externalNullifier = genExternalNullifier("voting-1");

    const FastSemaphore = await ethers.getContractFactory("FastSemaphore", {
      libraries: {
        PoseidonT3: poseidonT3.address,
        PoseidonT6: poseidonT6.address,
      },
    });
    const fastSemaphore = await FastSemaphore.deploy(20, externalNullifier);
    await fastSemaphore.deployed();

    const leafIndex = 4;

    const idCommitments = [];

    for (let i = 0; i < leafIndex; i++) {
      const tmpIdentity = genIdentity();
      const tmpCommitment = genIdentityCommitment(tmpIdentity);
      idCommitments.push(tmpCommitment);
    }

    const promises = idCommitments.map(async (id) => {
      const index = await fastSemaphore.insertIdentity(id);
      return index;
    });

    await Promise.all(promises);

    const identity = genIdentity();
    let signal = "yes";
    signal = Web3.utils.utf8ToHex(signal);
    const signalHash = genSignalHash(signal);
    const nullifierHash = genNullifierHash_poseidon(
      externalNullifier,
      identity.identityNullifier,
      20
    );
    const identityCommitment = genIdentityCommitment_poseidon(identity);

    await fastSemaphore.insertIdentity(identityCommitment);

    const wasmFilePath = path.join("./zkeyFiles", "semaphore.wasm");
    const finalZkeyPath = path.join("./zkeyFiles", "semaphore_final.zkey");

    idCommitments.push(identityCommitment);

    const witnessData = await genProof_fastSemaphore(
      identity,
      signalHash,
      idCommitments,
      externalNullifier,
      20,
      ZERO_VALUE,
      5,
      wasmFilePath,
      finalZkeyPath
    );

    const { fullProof, root } = witnessData;

    const pubSignals = [root, nullifierHash, signalHash, externalNullifier];

    const vKey = JSON.parse(
      fs.readFileSync("./zkeyFiles/verification_key.json", "utf-8")
    );

    const verified = await snarkjs.groth16.verify(
      vKey,
      pubSignals,
      fullProof.proof
    );

    expect(verified).to.equal(true);

    const canBroadcast = await fastSemaphore.preBroadcastCheck(
      root,
      nullifierHash,
      externalNullifier
    );

    expect(canBroadcast).to.equal(true);

    const res = await fastSemaphore.broadcastSignal(
      ethers.utils.hexlify(ethers.utils.toUtf8Bytes(signal)),
      root,
      nullifierHash,
      externalNullifier
    );

    expect(res.hash).to.be.an("string");
  });
});
