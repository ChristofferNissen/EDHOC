package edhoc;

public class Initiator {
	int methodCorr;
	int suite;
	int c_i; // bstr / int
		
	public Initiator(int method, int corr) {
		methodCorr = 4 * method + corr;
	}
	
	// Make message 1 and return it
	public int createMessage1() {
		suite = 0; // Some value
		c_i = 0; // Some value
		return 1; //message1
	}
	
	// Receive message 2, make and return message 3
	public int createMessage3(int message2) {
		return 3; //message3
	}
}