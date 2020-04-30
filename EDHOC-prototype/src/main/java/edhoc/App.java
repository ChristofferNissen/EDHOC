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

        // EDHOC parameters
        int METHOD_CORR = 4 * method + corr; 


        // Send out message one
        

        // send out message two

        // send out message three



		Initiator initiator = new Initiator(0,3);
		Responder responder = new Responder();
		int message1 = initiator.createMessage1();
		int message2 = responder.createMessage2(message1);
		int message3 = initiator.createMessage3(message2);
        boolean valid = responder.validateMessage3(message3);
        
        System.out.println("Valid: " + valid);
        
        
		
		EncryptMessage msg = new EncryptMessage();
		System.out.println( msg.getRecipientCount() );
    }
}
