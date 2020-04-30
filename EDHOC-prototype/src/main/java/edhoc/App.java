package edhoc;

/**
 * Hello world!
 *
 */
public class App 
{
    public static void main( String[] args )
    {
		Initiator initiator = new Initiator(0,3);
		Responder responder = new Responder();
		int message1 = initiator.createMessage1();
		int message2 = responder.createMessage2(message1);
		int message3 = initiator.createMessage3(message2);
		boolean valid = responder.validateMessage3(message3);
        System.out.println("Valid: " + valid);
    }
}
