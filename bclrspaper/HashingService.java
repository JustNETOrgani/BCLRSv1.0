package bclrspaper;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import it.unisa.dia.gas.jpbc.Element;

public class HashingService {
    /**
     * Base String-preimage overload, for any call site that
     * legitimately wants to hash a plain string (e.g. Q_ID_i's
     * hash-to-point in KeyManagementService, unlike the
     * abi.encode approach - that's a registration-time hash-to-curve over
     * userID+T_M, not one of the five preimages using abi.encode).
     */
    public void hash(Element target, String value) throws CryptoException {
        hash(target, value.getBytes());
    }

    /**
     * Hashes a raw byte preimage - specifically, the output of
     * AbiEncoder.encode(...), matching the SC's reduceToScalar
     * exactly: sha256(preimage) fed into JPBC's Element.setFromHash.
     */
    public void hash(Element target, byte[] preimage) throws CryptoException {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(preimage);
            target.setFromHash(digest, 0, digest.length);
        } catch (NoSuchAlgorithmException ex) {
            throw new CryptoException("SHA-256 hashing is not available", ex);
        }
    }
}
