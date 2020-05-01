package edhoc;

import COSE.*;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Random;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.security.interfaces.ECPublicKey;

import javax.crypto.KeyAgreement;
import java.io.Console;
import java.nio.ByteBuffer;
import java.util.*;

import static javax.xml.bind.DatatypeConverter.printHexBinary;
import static javax.xml.bind.DatatypeConverter.parseHexBinary;


/**
 * Hello world!
 *
 */
public class App 
{
    public static void main( String[] args ) throws NoSuchAlgorithmException
    {
		DiffieHellman dh = new ECDiffieHellman(256); // Keysize 256 for P-256
        int method = 0;
        int corr = 3;
		
		Initiator initiator = new Initiator(method, corr, dh);
		Responder responder = new Responder(dh);
		byte[] message1 = initiator.createMessage1();
        
        // send out message two
		byte[] message2 = responder.createMessage2(message1);

        // send out message three
		byte[] message3 = initiator.createMessage3(message2);

        boolean valid = responder.validateMessage3(message3);
        
        System.out.println("Valid: " + valid);
       
    }
}
