package edhoc;

import COSE.*;

import java.math.BigInteger;
import java.util.Random;


/**
 * Hello world!
 *
 */
public class App 
{
    public static void main( String[] args )
    {
		Random randomSource = new Random(42); // Totally perfect source of randomness
		DiffieHellman<BigInteger> dh = new IntegerDiffieHellman(5, 23); // Public parameters. Generator 5, modulus 23
		
		Initiator<BigInteger> initiator = new Initiator<BigInteger>(0, 3, dh, randomSource);
		Responder<BigInteger> responder = new Responder<BigInteger>(dh, randomSource);
		int message1 = initiator.createMessage1();
		int message2 = responder.createMessage2(message1);
		int message3 = initiator.createMessage3(message2);
		boolean valid = responder.validateMessage3(message3);
		System.out.println("Valid: " + valid);
		
		EncryptMessage msg = new EncryptMessage();
		System.out.println( msg.getRecipientCount() );
    }
}
