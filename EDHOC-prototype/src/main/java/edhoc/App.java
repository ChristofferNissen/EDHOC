package edhoc;

import java.io.IOException;

import java.security.NoSuchAlgorithmException;

import static javax.xml.bind.DatatypeConverter.printHexBinary;
import static edhoc.Helper.*;
/**
 * Hello world!
 *
 */
public class App 
{
    public static void main( String[] args ) throws NoSuchAlgorithmException, IOException
    {
        // Fixed parameters for our project
		ECDiffieHellman dh = new ECDiffieHellman(256); // Keysize 256 for P-256
		
		Initiator initiator = new Initiator(dh);
        Responder responder = new Responder(dh);

        byte[] message1 = initiator.createMessage1();

        if (message1 == null) {
            System.out.println("Initiator aborted early.");
            return;
        }

        System.out.println( "Initiator sends: " + printHexBinary(message1) );
            
        byte[] message2 = responder.createMessage2(message1);
        
        if (message2 == null) {
            System.out.println( "Responder aborted early.");
            return;
        }

        System.out.println( "Responder sends: " + printHexBinary(message2) );

        byte[] message3 = initiator.createMessage3(message2);

        if (message3 == null) {
            System.out.println( "Initiator aborted early.");
            return;
        }

        System.out.println( "Initiator sends: " + printHexBinary(message3) );
    }
}
