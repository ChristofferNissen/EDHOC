package edhoc;

import java.math.BigInteger;

public interface DiffieHellman<T> {
    T generator();
    BigInteger order();
    T power(T base, BigInteger exponent);
}