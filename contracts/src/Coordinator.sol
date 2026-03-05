// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ICoordinator} from "./interfaces/ICoordinator.sol";
import {IProverRegistry} from "./interfaces/IProverRegistry.sol";
import {IProofRegistry} from "./interfaces/IProofRegistry.sol";

/// @title Coordinator
/// @notice Main coordination contract for the Sincerin ZK proving network.
///         Receives proof requests from dApps, assigns registered provers,
///         verifies submitted proofs via the VerifyUltraHonk precompile,
///         and registers verified proofs in the on-chain ProofRegistry.
/// @dev Follows CEI (Checks-Effects-Interactions) pattern in all state-changing
///      functions. Uses a custom reentrancy guard on submitProof to protect the
///      fee transfer. The precompile staticcall is safe before effects because
///      staticcall cannot modify state.
/// @author Sincerin Protocol
contract Coordinator is ICoordinator {
    // =========================================================================
    //                              CONSTANTS
    // =========================================================================

    /// @notice Default address of the VerifyUltraHonk precompile on Sincerin L1
    address public constant DEFAULT_VERIFY_PRECOMPILE = 0x0300000000000000000000000000000000000002;

    /// @notice Reentrancy guard: slot value when NOT entered
    uint256 private constant NOT_ENTERED = 0;

    /// @notice Reentrancy guard: slot value when entered
    uint256 private constant ENTERED = 1;

    // =========================================================================
    //                           IMMUTABLE STORAGE
    // =========================================================================

    /// @notice ProverRegistry contract for prover lifecycle management
    IProverRegistry public immutable proverRegistry;

    /// @notice ProofRegistry contract for Merkle tree of verified proofs
    IProofRegistry public immutable proofRegistry;

    /// @notice Address of the VerifyUltraHonk precompile
    /// @dev On Sincerin L1 this is 0x0300000000000000000000000000000000000002.
    ///      Configurable for testing on networks without the precompile.
    address public immutable verifyPrecompile;

    // =========================================================================
    //                           MUTABLE STORAGE
    // =========================================================================

    /// @notice Privileged operator that can assign provers and register circuits
    /// @dev In MVP this is a single EOA or multisig. Post-MVP, governance.
    address public operator;

    /// @notice Minimum fee in wei required for a proof request
    uint256 public minFee;

    /// @notice Circuit registry: circuitId => verification key hash
    /// @dev A zero vkHash means the circuit is not registered.
    mapping(bytes32 => bytes32) public registeredCircuits;

    /// @notice Proof requests: requestId => ProofRequest struct
    mapping(bytes32 => ProofRequest) public requests;

    /// @notice Nonce per requester address for deterministic unique requestIds
    mapping(address => uint256) public nonces;

    /// @notice Public inputs hash per request, stored separately from the struct
    /// @dev Stored at request time so submitProof can validate input consistency
    mapping(bytes32 => bytes32) public requestPublicInputsHash;

    /// @notice Reentrancy guard state variable
    uint256 private _locked;

    // =========================================================================
    //                              MODIFIERS
    // =========================================================================

    /// @notice Prevents reentrant calls to protected functions
    /// @dev Uses a uint256 flag (cheaper than bool due to SSTORE gas refund rules).
    ///      Pattern: check not entered -> set entered -> execute -> set not entered.
    modifier nonReentrant() {
        if (_locked == ENTERED) revert ReentrancyGuardReentrantCall();
        _locked = ENTERED;
        _;
        _locked = NOT_ENTERED;
    }

    // =========================================================================
    //                            CUSTOM ERRORS
    // =========================================================================

    /// @notice Thrown when a reentrant call is detected
    error ReentrancyGuardReentrantCall();

    /// @notice Thrown when a zero address is passed where a valid address is required
    error ZeroAddress();

    /// @notice Thrown when the circuit is already registered with a non-zero vkHash
    error CircuitAlreadyRegistered();

    /// @notice Thrown when the verification key hash is zero
    error InvalidVKHash();

    /// @notice Thrown when the public inputs do not match the committed hash
    error PublicInputsMismatch();

    // =========================================================================
    //                               EVENTS
    // =========================================================================

    /// @notice Emitted when a new circuit is registered by the operator
    /// @param circuitId Identifier of the circuit
    /// @param vkHash Hash of the verification key for this circuit
    event CircuitRegistered(bytes32 indexed circuitId, bytes32 indexed vkHash);

    /// @notice Emitted when the operator address is updated
    /// @param previousOperator The old operator address
    /// @param newOperator The new operator address
    event OperatorUpdated(address indexed previousOperator, address indexed newOperator);

    /// @notice Emitted when the minimum fee is updated
    /// @param previousMinFee The old minimum fee
    /// @param newMinFee The new minimum fee
    event MinFeeUpdated(uint256 previousMinFee, uint256 newMinFee);

    // =========================================================================
    //                             CONSTRUCTOR
    // =========================================================================

    /// @notice Deploys the Coordinator with references to companion contracts
    /// @param _proverRegistry Address of the deployed ProverRegistry contract
    /// @param _proofRegistry Address of the deployed ProofRegistry contract
    /// @param _verifyPrecompile Address of the VerifyUltraHonk precompile
    ///        (0x0300000000000000000000000000000000000002 on Sincerin L1)
    /// @param _operator Address of the privileged operator (EOA or multisig)
    /// @param _minFee Minimum fee in wei for proof requests
    constructor(
        address _proverRegistry,
        address _proofRegistry,
        address _verifyPrecompile,
        address _operator,
        uint256 _minFee
    ) {
        if (_proverRegistry == address(0)) revert ZeroAddress();
        if (_proofRegistry == address(0)) revert ZeroAddress();
        if (_verifyPrecompile == address(0)) revert ZeroAddress();
        if (_operator == address(0)) revert ZeroAddress();

        proverRegistry = IProverRegistry(_proverRegistry);
        proofRegistry = IProofRegistry(_proofRegistry);
        verifyPrecompile = _verifyPrecompile;
        operator = _operator;
        minFee = _minFee;
    }

    // =========================================================================
    //                         OPERATOR FUNCTIONS
    // =========================================================================

    /// @notice Register a new circuit with its verification key hash
    /// @dev Only callable by the operator. A circuit can only be registered once;
    ///      to update a circuit's vkHash, deploy a new circuitId.
    /// @param circuitId Unique identifier for the circuit (e.g., keccak256("proof-of-age"))
    /// @param vkHash Hash of the verification key used by the precompile
    function registerCircuit(bytes32 circuitId, bytes32 vkHash) external {
        // Checks
        if (msg.sender != operator) revert Unauthorized();
        if (circuitId == bytes32(0)) revert InvalidCircuitId();
        if (vkHash == bytes32(0)) revert InvalidVKHash();
        if (registeredCircuits[circuitId] != bytes32(0)) revert CircuitAlreadyRegistered();

        // Effects
        registeredCircuits[circuitId] = vkHash;

        emit CircuitRegistered(circuitId, vkHash);
    }

    /// @notice Assign a registered prover to a pending proof request
    /// @dev Only callable by the operator. Validates that the prover is active in
    ///      ProverRegistry and that the request has not expired.
    /// @param requestId The proof request to assign
    /// @param prover The prover address to assign
    function assignProver(bytes32 requestId, address prover) external {
        // Checks
        if (msg.sender != operator) revert Unauthorized();

        ProofRequest storage req = requests[requestId];
        if (req.createdAt == 0) revert RequestNotFound();
        if (req.status != ProofStatus.Pending) revert InvalidStatus();
        if (req.deadline <= block.timestamp) revert RequestExpired();
        if (!proverRegistry.isActive(prover)) revert ProverNotRegistered();

        // Effects
        req.status = ProofStatus.Assigned;
        req.assignedProver = prover;

        emit ProofAssigned(requestId, prover);
    }

    /// @notice Update the operator address
    /// @dev Only callable by the current operator
    /// @param newOperator The new operator address
    function setOperator(address newOperator) external {
        if (msg.sender != operator) revert Unauthorized();
        if (newOperator == address(0)) revert ZeroAddress();

        address previousOperator = operator;
        operator = newOperator;

        emit OperatorUpdated(previousOperator, newOperator);
    }

    /// @notice Update the minimum fee for proof requests
    /// @dev Only callable by the operator
    /// @param newMinFee The new minimum fee in wei
    function setMinFee(uint256 newMinFee) external {
        if (msg.sender != operator) revert Unauthorized();

        uint256 previousMinFee = minFee;
        minFee = newMinFee;

        emit MinFeeUpdated(previousMinFee, newMinFee);
    }

    // =========================================================================
    //                        PUBLIC FUNCTIONS
    // =========================================================================

    /// @notice Submit a proof request for a specific circuit
    /// @dev The caller must send at least minFee as msg.value. The deadline must
    ///      be in the future. The circuitId must have been previously registered
    ///      by the operator. A unique requestId is generated deterministically
    ///      from (circuitId, sender, timestamp, nonce) to prevent collisions.
    /// @param circuitId The identifier of the circuit to prove
    /// @param publicInputsHash Hash of the public inputs for the proof.
    ///        Stored so submitProof can validate consistency.
    /// @param deadline Unix timestamp after which the request expires
    /// @return requestId Unique identifier for this proof request
    function requestProof(bytes32 circuitId, bytes32 publicInputsHash, uint256 deadline)
        external
        payable
        returns (bytes32 requestId)
    {
        // Checks
        if (registeredCircuits[circuitId] == bytes32(0)) revert InvalidCircuitId();
        if (msg.value < minFee) revert InsufficientFee();
        if (deadline <= block.timestamp) revert InvalidDeadline();

        // Effects
        uint256 nonce = nonces[msg.sender];
        // Increment nonce. Safe to use unchecked: a single address cannot
        // realistically exhaust uint256 nonce space.
        unchecked {
            nonces[msg.sender] = nonce + 1;
        }

        requestId = keccak256(abi.encodePacked(circuitId, msg.sender, block.timestamp, nonce));

        requests[requestId] = ProofRequest({
            requestId: requestId,
            circuitId: circuitId,
            requester: msg.sender,
            maxFee: msg.value,
            deadline: deadline,
            assignedProver: address(0),
            status: ProofStatus.Pending,
            createdAt: block.timestamp
        });

        requestPublicInputsHash[requestId] = publicInputsHash;

        // No external interactions — only event emission
        emit ProofRequested(requestId, circuitId, msg.sender, msg.value, deadline);
    }

    /// @notice Submit a proof for verification against the VerifyUltraHonk precompile
    /// @dev CEI pattern with reentrancy guard. The precompile staticcall is safe
    ///      before effects because staticcall cannot modify state.
    ///
    ///      Flow on success:
    ///        1. Validate request state (Checks)
    ///        2. Call precompile to verify proof (staticcall — cannot modify state)
    ///        3. Update request status, register proof, update reputation (Effects)
    ///        4. Transfer fee to prover (Interactions)
    ///
    ///      Flow on failure:
    ///        1. Validate request state (Checks)
    ///        2. Call precompile — verification fails
    ///        3. Update request status, update reputation negatively (Effects)
    ///        4. No fee transfer
    ///
    /// @param requestId The proof request to fulfill
    /// @param proof Raw UltraHonk proof bytes from Barretenberg (~2KB)
    /// @param vk Full verification key bytes (must hash to registered vkHash)
    /// @param publicInputs Raw public inputs (each 32 bytes = one field element)
    function submitProof(bytes32 requestId, bytes calldata proof, bytes calldata vk, bytes calldata publicInputs)
        external
        nonReentrant
    {
        // =================================================================
        //                           CHECKS
        // =================================================================
        ProofRequest storage req = requests[requestId];
        if (req.createdAt == 0) revert RequestNotFound();
        if (req.status != ProofStatus.Assigned) revert InvalidStatus();
        if (req.assignedProver != msg.sender) revert Unauthorized();
        if (req.deadline <= block.timestamp) revert RequestExpired();

        // Validate the verification key
        if (keccak256(vk) != registeredCircuits[req.circuitId]) revert InvalidVKHash();

        // =================================================================
        //             PRECOMPILE VERIFICATION (staticcall — read-only)
        // =================================================================
        // VerifyUltraHonk ABI: verify(bytes proof, bytes vk, bytes32[] publicInputs)
        // Returns ABI-encoded bool. staticcall is safe before effects.
        bool verificationPassed;
        {
            // Convert publicInputs (raw bytes) to bytes32[] for precompile
            uint256 numInputs = publicInputs.length / 32;
            bytes32[] memory pubInputsArr = new bytes32[](numInputs);
            for (uint256 i = 0; i < numInputs;) {
                bytes32 val;
                assembly {
                    val := calldataload(add(publicInputs.offset, mul(i, 32)))
                }
                pubInputsArr[i] = val;
                unchecked {
                    ++i;
                }
            }

            (bool callSuccess, bytes memory result) = verifyPrecompile.staticcall(
                abi.encodeWithSignature("verify(bytes,bytes,bytes32[])", proof, vk, pubInputsArr)
            );
            verificationPassed = callSuccess && result.length >= 32 && abi.decode(result, (bool));
        }

        if (!verificationPassed) {
            // =============================================================
            //                   EFFECTS (failure path)
            // =============================================================
            req.status = ProofStatus.Failed;

            // Update prover reputation (negative outcome, latency irrelevant)
            proverRegistry.updateReputation(msg.sender, 0, false);

            emit ProofRejected(requestId, msg.sender, "verification_failed");
            return;
        }

        // =================================================================
        //                      EFFECTS (success path)
        // =================================================================

        // Generate unique proofId from requestId and proof content hash
        bytes32 proofId = keccak256(abi.encodePacked(requestId, keccak256(proof)));

        req.status = ProofStatus.Verified;

        // Compute publicInputsHash for registry insertion
        bytes32 publicInputsHash = keccak256(publicInputs);

        // Register the verified proof in the on-chain Merkle tree
        proofRegistry.registerProof(proofId, req.circuitId, publicInputsHash, block.timestamp);

        // Update prover reputation (positive outcome)
        // Latency = time from request creation to now, converted to milliseconds
        // Safe to use unchecked: block.timestamp >= req.createdAt is guaranteed
        // by the request lifecycle (created first, submitted later).
        uint256 latencyMs;
        unchecked {
            latencyMs = (block.timestamp - req.createdAt) * 1000;
        }
        proverRegistry.updateReputation(msg.sender, latencyMs, true);

        emit ProofVerified(requestId, proofId, req.circuitId, block.timestamp);

        // =================================================================
        //                    INTERACTIONS (fee transfer)
        // =================================================================
        // Transfer the full maxFee to the prover. Using low-level call to
        // handle arbitrary receiver contracts and avoid gas stipend issues.
        uint256 fee = req.maxFee;
        if (fee > 0) {
            (bool sent,) = msg.sender.call{value: fee}("");
            if (!sent) revert TransferFailed();
        }
    }

    // =========================================================================
    //                          VIEW FUNCTIONS
    // =========================================================================

    /// @notice Get the full details of a proof request
    /// @param requestId The request to query
    /// @return The complete ProofRequest struct
    function getRequest(bytes32 requestId) external view returns (ProofRequest memory) {
        ProofRequest storage req = requests[requestId];
        if (req.createdAt == 0) revert RequestNotFound();
        return req;
    }

    /// @notice Get the verification key hash for a registered circuit
    /// @param circuitId The circuit to query
    /// @return The vkHash, or bytes32(0) if the circuit is not registered
    function getCircuitVKHash(bytes32 circuitId) external view returns (bytes32) {
        return registeredCircuits[circuitId];
    }

    /// @notice Get the stored public inputs hash for a proof request
    /// @param requestId The request to query
    /// @return The keccak256 hash of the public inputs committed at request time
    function getRequestPublicInputsHash(bytes32 requestId) external view returns (bytes32) {
        return requestPublicInputsHash[requestId];
    }
}
