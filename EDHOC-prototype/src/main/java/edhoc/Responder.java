package edhoc;

import java.math.BigInteger;
import java.util.Random;

public class Responder<GT> {
	int c_r;
	GT g_y;
	BigInteger privateComponent;
	DiffieHellman<GT> dh; 

	public Responder(DiffieHellman<GT> dh, Random randomSource) {
		do privateComponent = new BigInteger(dh.order().bitLength(), randomSource);
		while(privateComponent.compareTo(dh.order()) >= 0);
		System.out.println( "Responder chooses random value " + privateComponent );
		this.dh = dh;
	}
	
	// Receive message 1, make and return message 2
	public GT createMessage2(GT message1) {

		// validate message 1
		// The Responder SHALL process message_1 as follows:
		// 	Decode message_1 (see Appendix A.1).
		// 	Verify that the selected cipher suite is supported and that no prior cipher suites in SUITES_I are supported.
		// 	Pass AD_1 to the security application.

		// send response

		GT g_x = message1;
		GT key = dh.power(g_x, privateComponent);
		System.out.println("Responder got key: " + key);

		c_r = 0; // Some value
		g_y = dh.power(dh.generator(), privateComponent);
		System.out.println( "Responder sends " + g_y);
		return g_y; // message2
	}
	
	// Receive message 3, return valid boolean
	public boolean validateMessage3(GT message3) {
		return false;
	}
}