package edhoc;

import static javax.xml.bind.DatatypeConverter.printHexBinary;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import COSE.CoseException;

public class App {
    public static void main(String[] args) throws NoSuchAlgorithmException, IOException, CoseException {
        Security.addProvider(new BouncyCastleProvider());
 
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        System.out.println(kpg.getProvider());

        KeyPair initiatorPair = kpg.generateKeyPair();
        KeyPair respoderPair = kpg.generateKeyPair();

        // Fixed parameters for our project
        ECDiffieHellman dh = new ECDiffieHellman(256); // Keysize 256 for P-256

        Initiator initiator = new Initiator(dh, initiatorPair, respoderPair.getPublic());
        Responder responder = new Responder(dh, respoderPair, initiatorPair.getPublic());

        byte[] message1 = initiator.createMessage1();

        if (message1 == null) {
            System.out.println("Initiator aborted early.");
            return;
        }

        System.out.println("Initiator sends: " + printHexBinary(message1) + "\n");


        byte[] message2 = responder.createMessage2(message1);

        if (message2 == null) {
            System.out.println("Responder aborted early.");
            return;
        }

        System.out.println("Responder sends: " + printHexBinary(message2) + "\n");

        byte[] message3 = initiator.createMessage3(message2);

        if (message3 == null) {
            System.out.println("Initiator aborted early.");
            return;
        }

        System.out.println("Initiator sends: " + printHexBinary(message3) + "\n");

        boolean valid = responder.validateMessage3(message3);

        System.out.println("Message_3 valid: " + valid);

    }
}
