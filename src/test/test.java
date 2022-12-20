package test;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

public class test {
    public static void main(String[] args) {
        Pairing bp = PairingFactory.getPairing("data_ours/a.properties");
        Element P = bp.getG1().newRandomElement().getImmutable();
        Element G = bp.getG2().newRandomElement().getImmutable();
        Element s = bp.getZr().newRandomElement().getImmutable();
        Element S = bp.getG1().newRandomElement().getImmutable();
        for (int i = 0; i < 10; i++) {
            long start = System.currentTimeMillis();
            Element e = P.add(S).getImmutable();
            long end = System.currentTimeMillis();
            System.out.println((end - start));
        }
    }
}
