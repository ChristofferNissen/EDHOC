package edhoc;

import COSE.*;

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
}
