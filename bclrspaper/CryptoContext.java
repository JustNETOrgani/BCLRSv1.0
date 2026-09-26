package bclrspaper;

import java.nio.file.Files;
import java.nio.file.Path;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.plaf.jpbc.field.curve.EthBn254Gen;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

public class CryptoContext {
    private final cryptoParams cryptoParam;
    private Element masterPrivateKey;
    private Element masterPublicKeyG1; // = masterSecret * G1gen - used by the user to re-derive R_ID_i during blinding/unblinding
    private Element masterPublicKeyG2; // = masterSecret * G2gen - this is the contract's kgcPubKeyG2, used in the final pairing check

    // Fixed, meaningless, publicly-documented domain-separation string used
    // to derive H_FIXED below via hash-to-curve. Anyone can rerun this exact
    // string through the same hash-to-curve primitive and get the identical
    // point back hence publicly verifiable. This string must never change once a system is deployed.
    public static final String H_FIXED_SEED = "BCSCFFSKI-HFixed-v1";

    public CryptoContext() {
        this.cryptoParam = new cryptoParams();
    }

    public void initialize() throws CryptoException {
        String parameterFile = resolveParameterFile();
        cryptoParam.pairing = PairingFactory.getPairing(parameterFile);
        cryptoParam.G1 = cryptoParam.pairing.getG1();
        cryptoParam.G2 = cryptoParam.pairing.getG2();
        cryptoParam.Gt = cryptoParam.pairing.getGT();
        cryptoParam.Zr = cryptoParam.pairing.getZr();

        // Fixed, deterministic generators matching Ethereum's alt_bn128
        // precompiles and the Solidity contract's g1Gen()/g2Gen()/
        // hFixedGen() - not random elements.
        cryptoParam.G = EthBn254Gen.g1Generator(cryptoParam.G1).getImmutable();
        cryptoParam.G2gen = EthBn254Gen.g2Generator(cryptoParam.G2).getImmutable();

        // H_FIXED: the second, independent G1 generator used to build the
        // per-event key-image base H_ev = H(ev,tD)*H_FIXED.
        Element hFixed = cryptoParam.G1.newRandomElement();
        new HashingService().hash(hFixed, H_FIXED_SEED);
        cryptoParam.H_FIXED = hFixed.getImmutable();

        masterPrivateKey = cryptoParam.Zr.newRandomElement().invert().getImmutable();

        // The KGC's public key is published in BOTH groups. This is
        // standard practice for asymmetric-pairing schemes (publishing
        // s*G1 and s*G2 together is no easier to attack than either alone).
        masterPublicKeyG1 = cryptoParam.G.duplicate().mulZn(masterPrivateKey).getImmutable();
        masterPublicKeyG2 = cryptoParam.G2gen.duplicate().mulZn(masterPrivateKey).getImmutable();
    }

    public cryptoParams getCryptoParams() {
        return cryptoParam;
    }

    public Element getMasterPrivateKey() {
        return masterPrivateKey;
    }

    /** G1 element - used internally for the blinding-based key extraction. */
    public Element getMasterPublicKeyG1() {
        return masterPublicKeyG1;
    }

    /** G2 element - the contract's kgcPubKeyG2, used in the final ring-verify pairing check. */
    public Element getMasterPublicKeyG2() {
        return masterPublicKeyG2;
    }

    private String resolveParameterFile() throws CryptoException {
        if (Files.exists(Path.of("CryptoParameters", "params.properties"))) {
            return "CryptoParameters/params.properties";
        }
        if (Files.exists(Path.of("params.properties"))) {
            return "params.properties";
        }
        throw new CryptoException("Unable to locate params.properties for JPBC pairing initialization.");
    }
}
