package bclrspaper;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;

public class cryptoParams {
    public Pairing pairing;
    public Field<?> G1;
    public Field<?> G2;
    public Field<?> Gt;
    public Field<?> Zr;
    public Element G;       // fixed BN254 G1 generator (1, 2)
    public Element G2gen;   // fixed BN254 G2 generator, matches the Solidity contract's g2Gen()
    public Element H_FIXED; // second, independent G1 generator, matches the Solidity contract's hFixedGen()
}
