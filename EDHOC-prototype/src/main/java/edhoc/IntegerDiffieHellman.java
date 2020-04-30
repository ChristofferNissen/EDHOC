package edhoc;

import java.math.BigInteger;

public class IntegerDiffieHellman implements DiffieHellman<BigInteger> {
    private BigInteger modulus;
    private BigInteger generator;

    public IntegerDiffieHellman(int generator, int modulus){ 
        this(BigInteger.valueOf(generator), BigInteger.valueOf(modulus));
    }
    public IntegerDiffieHellman(BigInteger generator, BigInteger modulus) {
        this.generator = generator;
        this.modulus = modulus;
    }

    @Override
    public BigInteger order() {
        return modulus.add(BigInteger.valueOf(-1)); // Assuming modulus is a prime number
    }

    @Override
    public BigInteger power(BigInteger base, BigInteger exponent) {
        return base.modPow(exponent, modulus);
    }

    @Override
    public BigInteger generator() {
        return generator;
    }

}