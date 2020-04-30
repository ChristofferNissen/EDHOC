package edhoc;

public class Responder {
	int c_r;
	
	public Responder() {
	}
	
	// Receive message 1, make and return message 2
	public int createMessage2(int message1) {

		// validate message 1
		// The Responder SHALL process message_1 as follows:
		// 	Decode message_1 (see Appendix A.1).
		// 	Verify that the selected cipher suite is supported and that no prior cipher suites in SUITES_I are supported.
		// 	Pass AD_1 to the security application.

		// send response

		c_r = 0; // Some value
		return 2; // message2
	}
	
	// Receive message 3, return valid boolean
	public boolean validateMessage3(int message3) {
		return false;
	}
}