// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

// =============================================================================
// REQUIRED COMPILER SETTING - READ BEFORE DEPLOYING
// =============================================================================
// This must be set in your compiler config (Remix: Solidity Compiler tab ->
// "Advanced Configurations" -> "EVM VERSION" dropdown -> select "paris";
// Hardhat/Foundry: solidity.settings.evmVersion = "paris" in the config
// file). 
//
// WHY: solc >=0.8.24 defaults evmVersion to "cancun" when nothing is
// specified. At that setting, the optimizer emits PUSH0 (Shanghai, EIP-3855)
// and, in code paths that copy strings/structs in memory - e.g. this
// contract's publishUserPublicParams and the ring-membership chain-challenge
// hashing - MCOPY (Cancun, EIP-5656). If the actual deployment target (an
// older Remix VM selection, an older go-ethereum/besu/anvil version, or a
// chain that has not yet activated Cancun) does not support one of those
// opcodes, an opcode the target VM cannot execute.
//
// "paris" (the Merge, pre-Shanghai/pre-Cancun) avoids both PUSH0 and MCOPY
// and is supported by effectively every EVM-compatible environment in
// current use, which is why it is recommended here.
// =============================================================================

// A Smart Contract for SCFRSscheme
contract BscfRSscheme {

    // -------------------------------------------------------------------------
    // Structs
    // -------------------------------------------------------------------------
    struct G1Point {
        uint X;
        uint Y;
    }

    // G2 point over Fq²: each coordinate is (imaginary, real) component.
    struct G2Point {
        uint X_im;
        uint X_re;
        uint Y_im;
        uint Y_re;
    }

    struct PublicParams {
        address addrOfKGC;
        G1Point pubKeyX_G1; // G1 component, used by users to re-derive R_ID_i during blinded key extraction
        G2Point pubKeyX_G2; // G2 component used in pairing verification
    }

    struct SystemUsers {
        address userAddr;
        string  ID;
        G1Point U_ID_i;
        G1Point V_ID_i;
        G2Point W_ID_i;
        G1Point Q_ID_i;
    }

    // Bundles a signature's (A_s, B_s, keyImage) into a single memory
    // pointer. Passing these separately through ringVerify ->
    // ringVerifyWithMembership -> checkRingMembership -> deriveChainChallenge
    // (each of which also has its own locals: c, combinedBase, uidI,
    // combinedTarget, Ti, ...) overflows the EVM's 16-slot stack-access
    // window ("stack too deep"). Bundling into a struct keeps each of those
    /// functions to one stack slot for the whole group instead of several.
    struct SigCore {
        G1Point A_s;
        G1Point B_s;
        G1Point keyImage; // I = u_pi*H_ev - the bound key image
    }

    // Bundles the fields that stay constant across every iteration of the
    // ring-membership chain walk (checkRingMembership's loop / chainStep /
    // deriveChainChallenge) into one pointer, to prevent stack-depth problem.
    //
    // userListEncoding caches the abi.encode(userList) rendering of the ring
    // (see encodeUserList), built once in ringVerifyWithMembership via
    // encodeUserList and reused by every chainStep/deriveChainChallenge call thereafter.
    //
    // hAs caches the deterministic h_As = deriveHAs(message, A_s) value, computed once in
    // ringVerifyWithMembership and shared with checkRingMembership's chain
    // walk (via chainStep -> deriveChainChallenge).
    struct ChainCtx {
        string[] userList;
        string   message;
        string   ev;
        uint256  tD;
        bytes    userListEncoding;
        uint256  hAs;
    }

    // -------------------------------------------------------------------------
    // State
    // -------------------------------------------------------------------------
    // Generator of G1: the fixed point (1, 2). Inlined directly (rather than
    // via a separate g1Gen() helper).
    G1Point generator = G1Point(1, 2);

    // The curve/group order r (scalars/exponents live here — this is what
    // the off-chain JPBC Zr field uses, so hAsPrime must be reduced mod r.
    uint constant R_ORDER = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    address immutable addrOfKGC;

    mapping(address => PublicParams) public params;
    mapping(address => SystemUsers)  public user;
    mapping(string  => G1Point)      public idToUID; // identity string -> U_ID_i, for ring-membership lookup

    // -------------------------------------------------------------------------
    // Events
    // -------------------------------------------------------------------------
    event PublicParamsPublished(string paramsPubMsg);
    event ScDeployment(string scfSCDeployed);
    event UserPublicParamPublished(string userPubParamPubMsg);
    event EmbedPartialPrivKeyPublished(uint sVal, G1Point yVal);

    // -------------------------------------------------------------------------
    // Constructor
    // -------------------------------------------------------------------------
    constructor() {
        addrOfKGC = msg.sender;
        emit ScDeployment("Smart Contract for Scheme deployed");
    }

    // -------------------------------------------------------------------------
    // Modifiers
    // -------------------------------------------------------------------------
    modifier onlyKGC() {
        require(msg.sender == addrOfKGC, "Caller is not the KGC");
        _;
    }

    // -------------------------------------------------------------------------
    // Public functions
    // -------------------------------------------------------------------------

    /// @notice KGC publishes its public parameters. Stored under addrOfKGC.
    function publishPublicParams(G1Point memory kgcPubkeyG1, G2Point memory kgcPubkeyG2)
        public onlyKGC returns (bool)
    {
        params[addrOfKGC] = PublicParams(addrOfKGC, kgcPubkeyG1, kgcPubkeyG2);
        emit PublicParamsPublished("Public params published by KGC");
        return true;
    }

    /// @notice Users publish their public parameters.
    function publishUserPublicParams(
        string  memory id,
        G1Point memory uId,
        G1Point memory vId,
        G2Point memory wid,
        G1Point memory qId
    ) public returns (bool) {
        user[msg.sender] = SystemUsers(msg.sender, id, uId, vId, wid, qId);
        idToUID[id] = uId;
        emit UserPublicParamPublished("Public params published by User");
        return true;
    }

    /// @notice KGC emits partial private key metadata.
    function publishEmbedPartialPrivKey(uint256 s, G1Point memory yID)
        public onlyKGC returns (bool)
    {
        emit EmbedPartialPrivKeyPublished(s, yID);
        return true;
    }

    /// @notice Verify ring signature.
    /// Verification equation: e(B_s, G2) = e(A_s * h_As_prime^{-1}, X_kgc_G2)
    /// sigKeyImage is I = u_pi*H_ev, the bound key image folded into the hash 
    /// preimage below exactly like A_s/B_s are, via its (X,Y) coordinates).
    function ringVerify(
        string[]  memory userList,
        string    memory message,
        SigCore   memory sig,
        string    memory ev,
        uint256   tD
    ) public view returns (bool) {
        // Public entry point: builds its own userListEncoding, since a
        // standalone caller of ringVerify (as opposed to
        // ringVerifyWithMembership) has no reason to know about, or share,
        // that internal detail.
        //
        // h_As is likewise computed fresh here rather than shared - there
        // is nothing to share it with in the standalone-call case.
        uint256 hAs = deriveHAs(message, sig.A_s);
        return ringVerifyCore(message, sig, ev, tD, hAs, encodeUserList(userList));
    }

    /// @dev Shared core of the KGC-binding pairing check, taking the ring's
    /// already-built userListEncoding rather than building it itself - this
    /// lets ringVerifyWithMembership build it exactly once (in
    /// encodeUserList) and hand the same copy to both this check and
    /// checkRingMembership, rather than each independently paying the same
    /// O(n^2) build cost. ringVerify (the public entry point above) still
    /// builds its own when called standalone, since there is nothing to
    /// share in that case. Takes userListEncoding instead of the raw
    /// userList since that's now all deriveHAsPrime needs - userList itself
    /// is never otherwise touched by the pairing check.
    ///
    /// Takes hAs as an explicit parameter (deriveHAs(message, sig.A_s),
    /// computed by the caller) rather than reading it off sig.
    function ringVerifyCore(
        string    memory message,
        SigCore   memory sig,
        string    memory ev,
        uint256   tD,
        uint256   hAs,
        bytes     memory userListEncoding
    ) internal view returns (bool) {
        require(
            params[addrOfKGC].pubKeyX_G2.X_re != 0 || params[addrOfKGC].pubKeyX_G2.Y_re != 0,
            "KGC public params not initialised"
        );

        // Guard every caller-supplied G1 point that reaches a precompile
        // below before it does.
        requireOnCurve(sig.A_s, "sig.A_s");
        requireOnCurve(sig.B_s, "sig.B_s");

        uint256 hAsPrime    = deriveHAsPrime(message, ev, userListEncoding, tD, sig.keyImage, hAs);
        G1Point memory lhs  = sig.B_s;                                       // e(B_s, G2)
        G1Point memory rhs  = mul(sig.A_s, inverseMod(hAsPrime, R_ORDER));   // e(A_s * h'^{-1}, X_kgc)

        G2Point memory g2gen = g2Gen();
        G2Point memory kgcG2 = params[addrOfKGC].pubKeyX_G2;

        // Pairing check: e(lhs, g2gen) * e(-rhs, kgcG2) == 1
        // Implemented as: e(lhs, g2gen) == e(rhs, kgcG2)
        // Using two-pair check: e(lhs, g2gen) * e(neg_rhs, kgcG2) == 1
        G1Point memory neg_rhs = negate(rhs);

        return bn128CheckPairing([
            lhs.X,      lhs.Y,
            g2gen.X_im, g2gen.X_re, g2gen.Y_im, g2gen.Y_re,
            neg_rhs.X,  neg_rhs.Y,
            kgcG2.X_im, kgcG2.X_re, kgcG2.Y_im, kgcG2.Y_re
        ]);
    }

    /// @notice Full ring signature verification: KGC-binding pairing check
    /// PLUS the ring-membership OR-proof over u_i, 
    /// over the combined base/target bound to the key image.
    /// Both must pass.
    /// U_ID_i for each ring member is looked up on-chain via idToUID,
    /// populated at registration.
    function ringVerifyWithMembership(
        string[]  memory userList,
        string    memory message,
        SigCore   memory sig,
        string    memory ev,
        uint256   tD,
        uint256   eStart,
        uint256[] memory z
    ) public view returns (bool) {
        bytes memory userListEncoding = encodeUserList(userList);
        // hAs is likewise built exactly ONCE here and shared between the
        // pairing check and the chain walk (via ChainCtx.hAs), matching
        // userListEncoding's treatment immediately above.
        uint256 hAs = deriveHAs(message, sig.A_s);
        bool pairingOk = ringVerifyCore(message, sig, ev, tD, hAs, userListEncoding);
        ChainCtx memory ctx = ChainCtx(userList, message, ev, tD, userListEncoding, hAs);
        bool chainOk = checkRingMembership(ctx, sig, eStart, z);
        return pairingOk && chainOk;
    }

    /// @dev Recomputes the AOS-style ring-membership chain and checks
    /// closure, over the combined base g1'=g1+c*H_ev and combined per-slot
    /// target U_i'=U_ID_i+c*sigKeyImage, matching the Java backend's
    /// RingSignatureService.ringVerify exactly. H_ev is computed here, on
    /// -chain, from (ev,tD) via deriveHEv. Per-iteration work lives in
    /// chainStep below, kept as its own small stack frame.
    ///
    /// cI = c*sigKeyImage is computed ONCE here rather than inside the loop:
    /// c and sigKeyImage are both fixed for the whole proof (neither depends
    /// on the per-slot index), so recomputing this scalar mult on every one
    /// of the n iterations - as an earlier revision of this function did -
    /// was n-1 wasted G1 scalar multiplications. Hoisting it here reduces
    /// checkRingMembership's cost from 3n to 2n G1 scalar mults (chainStep
    /// now only performs the two that genuinely vary per slot), matching
    /// the same optimization RingSign already applies on the signing side.
    function checkRingMembership(
        ChainCtx  memory ctx,
        SigCore   memory sig,
        uint256   eStart,
        uint256[] memory z
    ) internal view returns (bool) {
        require(z.length == ctx.userList.length, "z length mismatch");
        requireOnCurve(sig.keyImage, "sig.keyImage");
        uint256 c = deriveC(sig.keyImage, ctx.userListEncoding, ctx.ev, ctx.tD);
        G1Point memory H_ev = deriveHEv(ctx.ev, ctx.tD);
        G1Point memory combinedBase = add(generator, mul(H_ev, c));
        G1Point memory cI = mul(sig.keyImage, c);
        uint256 eCur = eStart;
        for (uint i = 0; i < ctx.userList.length; i++) {
            eCur = chainStep(ctx, sig, combinedBase, cI, i, eCur, z[i]);
        }
        return eCur == eStart;
    }

    /// @dev Builds an unambiguous encoding of a ring's identity list, used
    /// as a hash input by deriveC/deriveChainChallenge/deriveHAsPrime.
    /// Factored out so checkRingMembership's caller can build this exactly
    /// once and hand the result to every consumer that needs it (deriveC,
    /// deriveChainChallenge via chainStep, ringVerifyCore) instead of each
    /// of them rebuilding it independently.
    function encodeUserList(string[] memory userList) internal pure returns (bytes memory) {
        return abi.encode(userList);
    }

    /// @dev One step of the ring-membership chain walk: recomputes T_i for
    /// slot idx from the combined base/target and folds it into the next
    /// challenge. Split out from checkRingMembership purely to keep each
    /// function's live-variable count under the EVM's stack-access window.
    /// Takes the already-computed cI = c*sigKeyImage (see checkRingMembership)
    /// rather than c itself, since c alone was never used here for anything
    /// but deriving cI - passing cI directly removes the last per-slot G1
    /// scalar multiplication that varied only in appearance, not in value.
    function chainStep(
        ChainCtx  memory ctx,
        SigCore   memory sig,
        G1Point   memory combinedBase,
        G1Point   memory cI,
        uint256   idx,
        uint256   eCur,
        uint256   zIdx
    ) internal view returns (uint256) {
        G1Point memory uidPoint = idToUID[ctx.userList[idx]];
        requireOnCurve(uidPoint, ctx.userList[idx]);
        G1Point memory combinedTarget = add(uidPoint, cI);
        G1Point memory Ti = add(mul(combinedBase, zIdx), negate(mul(combinedTarget, eCur)));
        return deriveChainChallenge(sig, ctx, idx, Ti);
    }

    /// @dev H_ev = H(ev,tD) * H_FIXED - computed on-chain, deterministically,
    /// from public inputs only, so no caller can substitute a different
    /// point. One G1 scalar multiplication against the fixed generator -
    /// no hash-to-curve on-chain.
    function deriveHEv(string memory ev, uint256 tD) internal view returns (G1Point memory) {
        bytes memory preimage = abi.encode(ev, tD);
        uint256 scalar = reduceToScalar(preimage);
        return mul(hFixedGen(), scalar);
    }

    /// @dev sha256-then-halve-until-<=R_ORDER reduction, factored out of
    /// deriveChainChallenge/deriveC/deriveHAsPrime/deriveHEv since it is
    /// the exact same operation everywhere it appears: mirrors JPBC's Zr ZrElement.setFromHash.
    function reduceToScalar(bytes memory preimage) internal pure returns (uint256) {
        bytes32 digest = sha256(preimage);
        uint256 val = uint256(digest);
        while (val > R_ORDER) {
            val = val / 2;
        }
        return val;
    }

    /// @dev Chain-challenge hash. sigKeyImage (a G1Point) contributes X and Y
    ///      coordinates instead of a single value.
    ///      Takes the ring's already-built userListEncoding.
    function deriveChainChallenge(
        SigCore   memory sig,
        ChainCtx  memory ctx,
        uint256   idx,
        G1Point   memory tI
    ) internal pure returns (uint256) {
        bytes memory sigEncoding = abi.encode(
            sig.A_s.X, sig.A_s.Y,
            sig.B_s.X, sig.B_s.Y,
            sig.keyImage.X, sig.keyImage.Y,
            ctx.hAs
        );
        bytes memory preimage = abi.encode(
            sigEncoding, ctx.userListEncoding, ctx.message, ctx.ev, ctx.tD, idx, tI.X, tI.Y
        );
        return reduceToScalar(preimage);
    }

    /// @dev c = H(I, L, ev, tD), the Fiat-Shamir coefficient combining the
    ///      ring-membership statement with the key-image statement into
    ///      one chain.
    ///
    ///      Takes the ring's already-built userListEncoding, same reasoning
    ///      as deriveChainChallenge above - this is only called once per
    ///      checkRingMembership invocation, so reusing rather than
    ///      rebuilding here saves a constant one-time O(n^2) rebuild.
    function deriveC(
        G1Point  memory keyImage,
        bytes    memory userListEncoding,
        string   memory ev,
        uint256  tD
    ) internal pure returns (uint256) {
        bytes memory preimage = abi.encode(keyImage.X, keyImage.Y, userListEncoding, ev, tD);
        return reduceToScalar(preimage);
    }

    // -------------------------------------------------------------------------
    // Internal utilities
    // -------------------------------------------------------------------------

    /// @dev h_As = H6(message || A_s), a deterministic scalar derived from
    /// data the verifier already has - not a signer-published field.
    function deriveHAs(string memory message, G1Point memory aS) internal pure returns (uint256) {
        bytes memory preimage = abi.encode(message, aS.X, aS.Y);
        return reduceToScalar(preimage);
    }

    /// @dev Binds the pairing check to (message, ev, ring, tD, keyImage, h_As).
    ///
    ///      Takes the ring's already-built userListEncoding (see
    ///      encodeUserList) rather than the raw userList, so
    ///      ringVerifyWithMembership can share one build across this and
    ///      checkRingMembership instead of each paying for it independently.
    ///
    ///      Takes hAs as an explicit parameter (deriveHAs(message, A_s),
    ///      computed by the caller - ringVerify or ringVerifyWithMembership)
    ///      rather than a signature field.
    function deriveHAsPrime(
        string  memory message,
        string  memory ev,
        bytes   memory userListEncoding,
        uint256 tD,
        G1Point memory sigKeyImage,
        uint256 hAs
    ) internal pure returns (uint256) {
        bytes memory preimage = abi.encode(message, ev, userListEncoding, tD, sigKeyImage.X, sigKeyImage.Y, hAs);
        return reduceToScalar(preimage);
    }

    /// @dev G1 point addition via BN128 precompile (address 6).
    function add(G1Point memory p1, G1Point memory p2) internal view returns (G1Point memory r) {
        uint[4] memory input;
        input[0] = p1.X;
        input[1] = p1.Y;
        input[2] = p2.X;
        input[3] = p2.Y;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 6, input, 0x80, r, 0x40)
        }
        require(success, "bn256 add failed");
    }

    /// @dev Scalar multiplication on G1 via BN128 precompile (address 7).
    function mul(G1Point memory p, uint s) internal view returns (G1Point memory r) {
        uint[3] memory input;
        input[0] = p.X;
        input[1] = p.Y;
        input[2] = s;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 7, input, 0x60, r, 0x40)
        }
        require(success, "bn256 scalar mul failed");
    }

    /// @dev Negate a G1 point (reflect over x-axis mod field prime).
    function negate(G1Point memory p) internal pure returns (G1Point memory) {
        uint FIELD_PRIME = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
        if (p.X == 0 && p.Y == 0) return G1Point(0, 0);
        return G1Point(p.X, FIELD_PRIME - (p.Y % FIELD_PRIME));
    }

    /// @dev Curve-membership check for G1 points: y^2 = x^3 + 3 (mod q),
    /// with (0,0) accepted as the EIP-196 point-at-infinity encoding.
    /// Every G1 point that reaches ecAdd/ecMul/ecPairing but did NOT come
    /// from an on-chain scalar-mult of a known-good generator (i.e. every
    /// caller-supplied or storage-read point: sig.A_s, sig.B_s,
    /// sig.keyImage, idToUID[...] lookups, and hFixedGen()) must be
    /// checked with this before use. Malformed/off-curve input to those
    /// precompiles is documented, in common client implementations, to
    /// consume ALL forwarded gas instead of failing with a cheap revert.
    /// Checking here converts that into an immediate, cheap, clearly-labeled
    /// revert identifying exactly which point is bad.
    function isOnCurveG1(G1Point memory p) internal pure returns (bool) {
        uint FIELD_PRIME = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
        if (p.X == 0 && p.Y == 0) {
            return true;
        }
        if (p.X >= FIELD_PRIME || p.Y >= FIELD_PRIME) {
            return false; // coordinates must already be reduced mod q
        }
        uint256 lhs = mulmod(p.Y, p.Y, FIELD_PRIME);
        uint256 rhs = addmod(
            mulmod(mulmod(p.X, p.X, FIELD_PRIME), p.X, FIELD_PRIME),
            3,
            FIELD_PRIME
        );
        return lhs == rhs;
    }

    /// @dev require(isOnCurveG1(p), ...) with a label folded into the
    /// revert reason, so a bad point is identified by name (which ring
    /// slot / which signature field) rather than a bare "false".
    function requireOnCurve(G1Point memory p, string memory label) internal pure {
        require(
            isOnCurveG1(p),
            string(abi.encodePacked(label, ": G1 point is not on the BN254 curve (malformed, wrong field, or unregistered identity)"))
        );
    }

    /// @dev BN128 G2 generator (EIP-197 / EIP-196 standard coordinates).
    function g2Gen() internal pure returns (G2Point memory) {
        return G2Point(
            11559732032986387107991004021392285783925812861821192530917403151452391805634,
            10857046999023057135944570762232829481370756359578518086990519993285655852781,
            4082367875863433681332203403145435568316851327593401208105741076214120093531,
            8495653923123431417604973247489272438418190587263600148770280649306958101930
        );
    }

    /// @dev H_FIXED: a second, independent G1 generator with unknown
    /// discrete log relative to the G1 generator (1,2), used only to build
    /// the per-event key-image base H_ev = H(ev,tD)*H_FIXED. Generated via
    /// GenerateHFixed.java's hash-to-curve on the fixed seed
    /// "BCSCFFSKI-HFixed-v1" (CryptoContext.H_FIXED_SEED).
    ///
    /// These coordinates satisfy y^2 = x^3+3 (mod q), i.e. they are a
    /// genuine point on the curve, not the point at infinity. That
    /// on-curve check is what the require() below enforces on every call,
    /// so a future accidental reintroduction of a bad constant here fails
    /// loudly instead of silently burning gas in the ecMul precompile
    /// inside deriveHEv.
    function hFixedGen() internal pure returns (G1Point memory) {
        G1Point memory h = G1Point(
            18578364905426123686847963464168493510202475543320800656315368226161095246754,
            18092712915890995599559169202626743240368639481085399883944636861726335588495
        );
        require(
            isOnCurveG1(h) && !(h.X == 0 && h.Y == 0),
            "hFixedGen: constant is not a valid, non-infinity BN254 G1 point - see GenerateHFixed.java"
        );
        return h;
    }

    /// @dev BN128 pairing check via precompile 0x08. Input: two (G1, G2) pairs = 12 uint256s.
    function bn128CheckPairing(uint256[12] memory input) public view returns (bool) {
        uint256[1] memory result;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 0x08, input, 384, result, 32)
        }
        require(success, "bn128 pairing precompile failed");
        return result[0] == 1;
    }

    /// @dev Extended Euclidean modular inverse. The divide-then-multiply
    /// step below (q = r1/r2, then t1 - int(q)*t2) and t1's reliance on
    /// Solidity's implicit zero-default are both flagged by generic static
    /// analysis (divide-before-multiply, uninitialized-local), but both are
    /// the textbook, correct extended-Euclidean-algorithm recurrence, not a
    /// precision-loss bug.
    function inverseMod(uint u, uint m) internal pure returns (uint) {
        if (m == 0) return 0;
        if (u >= m) u = u % m;
        if (u == 0) return 0;

        int t1 = 0;
        int t2 = 1;
        uint r1 = m;
        uint r2 = u;
        uint q;

        while (r2 != 0) {
            q = r1 / r2;
            // slither-disable-next-line divide-before-multiply
            (t1, t2, r1, r2) = (t2, t1 - int(q) * t2, r2, r1 - q * r2);
        }

        if (t1 < 0) return (m - uint(-t1));
        return uint(t1);
    }
}
