package edhoc;

import java.math.BigInteger;
import java.util.Random;

public class Initiator<GT> {
	int methodCorr;
	int suite;
	int c_i; // bstr / int
	private GT g_x;
	private BigInteger privateComponent;
	private DiffieHellman<GT> dh;

	public Initiator(int method, int corr, DiffieHellman<GT> dh, Random randomSource) {
		methodCorr = 4 * method + corr;
		do privateComponent = new BigInteger(dh.order().bitLength(), randomSource);
		while(privateComponent.compareTo(dh.order()) >= 0);
		System.out.println( "Initiator chooses random value " + privateComponent );
		this.dh = dh;
	}
	
	// Make message 1 and return it
	public int createMessage1() {
		suite = 0; // Some value
		c_i = 0; // Some value
		g_x = dh.power(dh.generator(), privateComponent);
		System.out.println( "Initiator sends " + g_x);
		return 1; //message1
	}
	
	// Receive message 2, make and return message 3
	public int createMessage3(int message2) {
		return 3; //message3
	}
}