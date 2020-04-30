package edhoc;

import COSE.*;
import java.util.Base64;
import java.security.MessageDigest;

/**
 * Hello world!
 *
 */
public class App 
{
    public static void main( String[] args )
    {

        // Fixed parameters for our project
        int method = 0;
        int corr = 3;
		Initiator initiator = new Initiator(method,corr);
		Responder responder = new Responder();

        // Send out message one
		int message1 = initiator.createMessage1();
        
        // send out message two
		int message2 = responder.createMessage2(message1);

        // send out message three
		int message3 = initiator.createMessage3(message2);

        boolean valid = responder.validateMessage3(message3);
        
        System.out.println("Valid: " + valid);
        
        
		
		EncryptMessage msg = new EncryptMessage();
		System.out.println( msg.getRecipientCount() );
    }
	
	public static byte[] sha256Hashing(byte[] cborEncodedBytes) {
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			byte[] hashedBytes = md.digest(cborEncodedBytes);
			String encoded = Base64.getEncoder().encodeToString(hashedBytes);
			// Encode String with cbor
			return null; // Return encoded string
		} catch (Exception e) {
			System.out.println("Hashing algorith not valid");
			return null;
		}
	}
}
