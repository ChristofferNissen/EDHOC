package edhoc;

import java.io.IOException;

import edhoc.model.Message;
import edhoc.model.MessageOne;
import edhoc.model.MessageTwo;

/**
 * Hello world!
 *
 */
public class App {
    public static void main(String[] args) {

        // Fixed parameters for our project
        int method = 0;
        int corr = 3;

        // EDHOC parameters
        int METHOD_CORR = 4 * method + corr;

        // Send out message one

        // send out message two

        // send out message three

        Initiator initiator = new Initiator(0, 3);
        Responder responder = new Responder();
        int message1 = initiator.createMessage1();
        int message2 = responder.createMessage2(message1);
        int message3 = initiator.createMessage3(message2);
        boolean valid = responder.validateMessage3(message3);

        System.out.println("Valid: " + valid);

        MessageTwo m1 = new MessageTwo(1);
        try {
            byte[] bytes = Helper.EncodeAsCbor(m1);
            MessageTwo org = Helper.DecodeM2FromCbor(bytes);
           
            System.out.println(bytes);
            System.out.println(m1.getMethod());
            System.out.println(org.getMethod());

            


        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        

		
		// EncryptMessage msg = new EncryptMessage();
		// System.out.println( msg.getRecipientCount() );
    }
}
