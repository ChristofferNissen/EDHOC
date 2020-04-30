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
	public int createMessage2(int message1) {
		c_r = 0; // Some value
		g_y = dh.power(dh.generator(), privateComponent);
		System.out.println( "Responder sends " + g_y);
		return 2; // message2
	}
	
	// Receive message 3, return valid boolean
	public boolean validateMessage3(int message3) {
		GT g_x = dh.generator(); // Read from message3
		GT key = dh.power(g_x, privateComponent);
		System.out.println("Responder got key: " + key);
		return false;
	}
}