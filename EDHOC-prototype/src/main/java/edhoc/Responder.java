package edhoc;

public class Responder {
	int c_r;
	
	public Responder() {
	}
	
	// Receive message 1, make and return message 2
	public int createMessage2(int message1) {
		c_r = 0; // Some value
		return 2; // message2
	}
	
	// Receive message 3, return valid boolean
	public boolean validateMessage3(int message3) {
		return false;
	}
}