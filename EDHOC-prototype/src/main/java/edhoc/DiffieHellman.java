package edhoc;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

public interface DiffieHellman {
    KeyPair generateKeyPair();
    PublicKey decodePublicKey(byte[] key);
    byte[] generateSecret(PrivateKey sk, PublicKey pk);
}