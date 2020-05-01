package edhoc;

import java.security.KeyPair;
import java.security.PublicKey;

import static javax.xml.bind.DatatypeConverter.printHexBinary;
import static javax.xml.bind.DatatypeConverter.parseHexBinary;

public class Responder {
	int c_r;
	KeyPair keyPair;
	DiffieHellman dh; 

	public Responder(DiffieHellman dh) {
		c_r = 0; // Some value
		keyPair = dh.generateKeyPair();
		System.out.println("Responder chooses random value " + printHexBinary(keyPair.getPrivate().getEncoded()));
		this.dh = dh;
	}
	
	// Receive message 1, make and return message 2
	public byte[] createMessage2(byte[] message1) {

		// validate message 1
		// The Responder SHALL process message_1 as follows:
		// 	Decode message_1 (see Appendix A.1).
		// 	Verify that the selected cipher suite is supported and that no prior cipher suites in SUITES_I are supported.
		// 	Pass AD_1 to the security application.

		// send response

		PublicKey pk = dh.decodePublicKey(message1);
		byte[] sharedSecret = dh.generateSecret(keyPair.getPrivate(), pk);
		System.out.println("Responder has shared secret: " + printHexBinary(sharedSecret));

		System.out.println( "Responder sends " + keyPair.getPublic());
		return keyPair.getPublic().getEncoded(); // message2
	}
	
	// Receive message 3, return valid boolean
	public boolean validateMessage3(byte[] message3) {
		return false;
	}
}