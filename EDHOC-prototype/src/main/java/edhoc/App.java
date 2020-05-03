package edhoc;

import java.io.IOException;

import edhoc.model.Message;
import edhoc.model.MessageOne;
import edhoc.model.MessageTwo;

import java.security.NoSuchAlgorithmException;

/**
 * Hello world!
 *
 */
public class App 
{
    public static void main( String[] args ) throws NoSuchAlgorithmException
    {
        // Fixed parameters for our project
		DiffieHellman dh = new ECDiffieHellman(256); // Keysize 256 for P-256
        int method = 0;
        int corr = 3;
		
		Initiator initiator = new Initiator(method, corr, dh);
        Responder responder = new Responder(dh);

		byte[] message1 = initiator.createMessage1();
		byte[] message2 = responder.createMessage2(message1);
		byte[] message3 = initiator.createMessage3(message2);

        MessageTwo m1 = new MessageTwo(1);
        try {
            byte[] bytes = Helper.encodeAsCbor(m1);
            MessageTwo org = Helper.DecodeM2FromCbor(bytes);
           
            System.out.println(bytes);
            System.out.println(m1.getMethod());
            System.out.println(org.getMethod());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
