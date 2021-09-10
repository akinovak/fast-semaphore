//SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.0;

import {IncrementalQuinTree} from "./IncrementalMerkleTree.sol";
import "./Ownable.sol";

contract FastSemaphore is Ownable, IncrementalQuinTree {
    // The external nullifier helps to prevent double-signalling by the same
    // user. An external nullifier can be active or deactivated.

    // Each node in the linked list
    struct ExternalNullifierNode {
        uint232 next;
        bool exists;
        bool isActive;
    }

    // We store the external nullifiers using a mapping of the form:
    // enA => { next external nullifier; if enA exists; if enA is active }
    // Think of it as a linked list.
    mapping(uint232 => ExternalNullifierNode)
        public externalNullifierLinkedList;

    uint256 public numExternalNullifiers = 0;

    // First and last external nullifiers for linked list enumeration
    uint232 public firstExternalNullifier = 0;
    uint232 public lastExternalNullifier = 0;

    // Whether broadcastSignal() can only be called by the owner of this
    // contract. This is the case as a safe default.
    bool public isBroadcastPermissioned = true;

    // Whether the contract has already seen a particular nullifier hash
    mapping(uint256 => bool) public nullifierHashHistory;

    mapping(uint256 => bytes) public signalIndexToSignal;

    // A mapping between signal indices to external nullifiers
    mapping(uint256 => uint256) public signalIndexToExternalNullifier;

    // The next index of the `signalIndexToSignal` mapping
    uint256 public nextSignalIndex = 0;

    event SignalBroadcast(uint256 indexed signalIndex);
    event PermissionSet(bool indexed newPermission);
    event ExternalNullifierAdd(uint232 indexed externalNullifier);
    event ExternalNullifierChangeStatus(
        uint232 indexed externalNullifier,
        bool indexed active
    );

    // This value should be equal to
    // 0x7d10c03d1f7884c85edee6353bd2b2ffbae9221236edde3778eac58089912bc0
    // which you can calculate using the following ethersjs code:
    // ethers.utils.solidityKeccak256(['bytes'], [ethers.utils.toUtf8Bytes('Semaphore')])
    // By setting the value of unset (empty) tree leaves to this
    // nothing-up-my-sleeve value, the authors hope to demonstrate that they do
    // not have its preimage and therefore cannot spend funds they do not own.

    uint256 public NOTHING_UP_MY_SLEEVE_ZERO =
        uint256(keccak256(abi.encodePacked("Semaphore"))) % SNARK_SCALAR_FIELD;

    /*
     * If broadcastSignal is permissioned, check if msg.sender is the contract
     * owner
     */
    modifier onlyOwnerIfPermissioned() {
        require(
            !isBroadcastPermissioned || isOwner(),
            "Semaphore: broadcast permission denied"
        );

        _;
    }

    /*
     * @param _treeLevels The depth of the identity tree.
     * @param _firstExternalNullifier The first identity nullifier to add.
     */
    constructor(uint8 _treeLevels, uint232 _firstExternalNullifier)
        IncrementalQuinTree(_treeLevels, NOTHING_UP_MY_SLEEVE_ZERO)
        Ownable()
    {
        addEn(_firstExternalNullifier, true);
    }

    function insertIdentity(uint256 _identityCommitment)
        public
        onlyOwner
        returns (uint256)
    {
        // Ensure that the given identity commitment is not the zero value
        require(
            _identityCommitment != NOTHING_UP_MY_SLEEVE_ZERO,
            "Semaphore: identity commitment cannot be the nothing-up-my-sleeve-value"
        );

        return insertLeaf(_identityCommitment);
    }

    function preBroadcastCheck(
        uint256 _root,
        uint256 _nullifiersHash,
        uint232 _externalNullifier
    ) public view returns (bool) {
        return
            nullifierHashHistory[_nullifiersHash] == false &&
            isExternalNullifierActive(_externalNullifier) &&
            rootHistory[_root] &&
            _root < SNARK_SCALAR_FIELD &&
            _nullifiersHash < SNARK_SCALAR_FIELD;
    }

    /*
     * A modifier which ensures that the signal and proof are valid.
     * @param _root The Merkle tree root
     * @param _nullifiersHash The nullifiers hash
     * @param _signalHash The signal hash
     * @param _externalNullifier The external nullifier
     */
    modifier isValidSignal(
        uint256 _root,
        uint256 _nullifiersHash,
        uint232 _externalNullifier
    ) {
        // Check whether the nullifier hash has been seen
        require(
            nullifierHashHistory[_nullifiersHash] == false,
            "Semaphore: nullifier already seen"
        );

        // Check whether the nullifier hash is active
        require(
            isExternalNullifierActive(_externalNullifier),
            "Semaphore: external nullifier not found"
        );

        // Check whether the given Merkle root has been seen previously
        require(rootHistory[_root], "Semaphore: root not seen");

        // Check whether _nullifiersHash is a valid field element.
        require(
            _nullifiersHash < SNARK_SCALAR_FIELD,
            "Semaphore: the nullifiers hash must be lt the snark scalar field"
        );
        _;
    }

    /*
     * Broadcasts the signal.
     * @param _signal The signal to broadcast
     * @param _proof The proof elements.
     * @param _root The root of the Merkle tree (the 1st public signal)
     * @param _nullifiersHash The nullifiers hash (the 2nd public signal)
     * @param _externalNullifier The nullifiers hash (the 4th public signal)
     */
    function broadcastSignal(
        bytes memory _signal,
        uint256 _root,
        uint256 _nullifiersHash,
        uint232 _externalNullifier
    )
        public
        onlyOwnerIfPermissioned
        isValidSignal(_root, _nullifiersHash, _externalNullifier)
    {
        uint256 signalIndex = nextSignalIndex;

        // store the signal
        signalIndexToSignal[nextSignalIndex] = _signal;

        // map the the signal index to the given external nullifier
        signalIndexToExternalNullifier[nextSignalIndex] = _externalNullifier;

        // increment the signal index
        nextSignalIndex++;

        // Store the nullifiers hash to prevent double-signalling
        nullifierHashHistory[_nullifiersHash] = true;

        emit SignalBroadcast(signalIndex);
    }

    /*
     * A private helper function which adds an external nullifier.
     * @param _externalNullifier The external nullifier to add.
     * @param _isFirst Whether _externalNullifier is the first external
     * nullifier. Only the constructor should set _isFirst to true when it
     * calls addEn().
     */
    function addEn(uint232 _externalNullifier, bool isFirst) private {
        if (isFirst) {
            firstExternalNullifier = _externalNullifier;
        } else {
            // The external nullifier must not have already been set
            require(
                externalNullifierLinkedList[_externalNullifier].exists == false,
                "Semaphore: external nullifier already set"
            );

            // Connect the previously added external nullifier node to this one
            externalNullifierLinkedList[lastExternalNullifier]
                .next = _externalNullifier;
        }

        // Add a new external nullifier
        externalNullifierLinkedList[_externalNullifier].next = 0;
        externalNullifierLinkedList[_externalNullifier].isActive = true;
        externalNullifierLinkedList[_externalNullifier].exists = true;

        // Set the last external nullifier to this one
        lastExternalNullifier = _externalNullifier;

        numExternalNullifiers++;

        emit ExternalNullifierAdd(_externalNullifier);
    }

    /*
     * Adds an external nullifier to the contract. This external nullifier is
     * active once it is added. Only the owner can do this.
     * @param _externalNullifier The new external nullifier to set.
     */
    function addExternalNullifier(uint232 _externalNullifier) public onlyOwner {
        addEn(_externalNullifier, false);
    }

    /*
     * Deactivate an external nullifier. The external nullifier must already be
     * active for this function to work. Only the owner can do this.
     * @param _externalNullifier The new external nullifier to deactivate.
     */
    function deactivateExternalNullifier(uint232 _externalNullifier)
        public
        onlyOwner
    {
        // The external nullifier must already exist
        require(
            externalNullifierLinkedList[_externalNullifier].exists,
            "Semaphore: external nullifier not found"
        );

        // The external nullifier must already be active
        require(
            externalNullifierLinkedList[_externalNullifier].isActive == true,
            "Semaphore: external nullifier already deactivated"
        );

        // Deactivate the external nullifier. Note that we don't change the
        // value of nextEn.
        externalNullifierLinkedList[_externalNullifier].isActive = false;

        emit ExternalNullifierChangeStatus(_externalNullifier, false);
    }

    /*
     * Reactivate an external nullifier. The external nullifier must already be
     * inactive for this function to work. Only the owner can do this.
     * @param _externalNullifier The new external nullifier to reactivate.
     */
    function reactivateExternalNullifier(uint232 _externalNullifier)
        public
        onlyOwner
    {
        // The external nullifier must already exist
        require(
            externalNullifierLinkedList[_externalNullifier].exists,
            "Semaphore: external nullifier not found"
        );

        // The external nullifier must already have been deactivated
        require(
            externalNullifierLinkedList[_externalNullifier].isActive == false,
            "Semaphore: external nullifier is already active"
        );

        // Reactivate the external nullifier
        externalNullifierLinkedList[_externalNullifier].isActive = true;

        emit ExternalNullifierChangeStatus(_externalNullifier, true);
    }

    /*
     * Returns true if and only if the specified external nullifier is active
     * @param _externalNullifier The specified external nullifier.
     */
    function isExternalNullifierActive(uint232 _externalNullifier)
        public
        view
        returns (bool)
    {
        return externalNullifierLinkedList[_externalNullifier].isActive;
    }

    /*
     * Returns the next external nullifier after the specified external
     * nullifier in the linked list.
     * @param _externalNullifier The specified external nullifier.
     */
    function getNextExternalNullifier(uint232 _externalNullifier)
        public
        view
        returns (uint232)
    {
        require(
            externalNullifierLinkedList[_externalNullifier].exists,
            "Semaphore: no such external nullifier"
        );

        uint232 n = externalNullifierLinkedList[_externalNullifier].next;

        require(
            numExternalNullifiers > 1 && externalNullifierLinkedList[n].exists,
            "Semaphore: no external nullifier exists after the specified one"
        );

        return n;
    }

    /*
     * Returns the number of inserted identity commitments.
     */
    function getNumIdentityCommitments() public view returns (uint256) {
        return nextLeafIndex;
    }

    /*
     * Sets the `isBroadcastPermissioned` storage variable, which determines
     * whether broadcastSignal can or cannot be called by only the contract
     * owner.
     * @param _newPermission True if the broadcastSignal can only be called by
     *                       the contract owner; and False otherwise.
     */
    function setPermissioning(bool _newPermission) public onlyOwner {
        isBroadcastPermissioned = _newPermission;

        emit PermissionSet(_newPermission);
    }
}
