package edhoc;

import COSE.*;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;


/**
 * Hello world!
 *
 */
public class App 
{
    public static void main( String[] args )
    {
		Random randomSource = new SecureRandom(); 
		DiffieHellman<BigInteger> dh = new IntegerDiffieHellman(5, 23); // Public parameters. Generator 5, modulus 23
        int method = 0;
        int corr = 3;
		
		Initiator<BigInteger> initiator = new Initiator<BigInteger>(method, corr, dh, randomSource);
		Responder<BigInteger> responder = new Responder<BigInteger>(dh, randomSource);
		BigInteger message1 = initiator.createMessage1();
        
        // send out message two
		BigInteger message2 = responder.createMessage2(message1);

        // send out message three
		BigInteger message3 = initiator.createMessage3(message2);

        boolean valid = responder.validateMessage3(message3);
        
        System.out.println("Valid: " + valid);
		
		EncryptMessage msg = new EncryptMessage();
		System.out.println( msg.getRecipientCount() );
    }
}
