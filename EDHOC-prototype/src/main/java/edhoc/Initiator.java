package edhoc;

import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Random;
import java.io.IOException;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;

import edhoc.model.Message;
import edhoc.model.MessageOne;

import static javax.xml.bind.DatatypeConverter.printHexBinary;
import static javax.xml.bind.DatatypeConverter.parseHexBinary;

public class Initiator {
	int methodCorr; // Method and correlation as a single value (specified in message_1)
	// Cipher Suite consists of: 
	//	* AEAD Algorithm
	//	* Hash Algorithm
	//	* Elliptic Curve
	//	* Signature Algorithm
	//	* Signature Algorithm Curve
	//	* AEAD algorithm
	//	* Application Hash Algorithm
	// Represents a specific suite consisting of an ordered set of COSE algorithms
	int suite = 2; // (AES-CCM-16-64-128, SHA-256, P-256, ES256, P-256, AES-CCM-16-64-128, SHA-256)
	int c_i; // bstr / int
	private KeyPair keyPair; // Pair of values for G_X and the private component
	private DiffieHellman dh;

	public Initiator(int method, int corr, DiffieHellman dh) {
		methodCorr = 4 * method + corr;
		this.dh = dh;

		keyPair = dh.generateKeyPair();
		System.out.println("Initiator chooses random value " + printHexBinary(keyPair.getPrivate().getEncoded()));
	}

	// Make message 1 and return it
	public byte[] createMessage1() {

		// The Initiator SHALL compose message_1 as follows:
		// The supported cipher suites and the order of preference MUST NOT be changed
		// based on previous error messages. However, the list SUITES_I sent to the
		// Responder MAY be truncated such that cipher suites which are the least
		// preferred are omitted. The amount of truncation MAY be changed between
		// sessions, e.g. based on previous error messages (see next bullet), but all
		// cipher suites which are more preferred than the least preferred cipher suite
		// in the list MUST be included in the list.
		// Determine the cipher suite to use with the Responder in message_1. If the
		// Initiator previously received from the Responder an error message to a
		// message_1 with diagnostic payload identifying a cipher suite that the
		// Initiator supports, then the Initiator SHALL use that cipher suite. Otherwise
		// the first supported (i.e. the most preferred) cipher suite in SUITES_I MUST
		// be used.
		// Generate an ephemeral ECDH key pair as specified in Section 5 of [SP-800-56A]
		// using the curve in the selected cipher suite and format it as a COSE_Key. Let
		// G_X be the 'x' parameter of the COSE_Key.
		// Choose a connection identifier C_I and store it for the length of the
		// protocol.
		// Encode message_1 as a sequence of CBOR encoded data items as specified in
		// Section 4.2.1

		Message m = new MessageOne(1);

		c_i = 0; // Some value

		System.out.println("Initiator sends " + keyPair.getPublic().toString());
		return keyPair.getPublic().getEncoded(); // message1
	}

	private byte[] EncodeAsCbor(Message m) throws IOException {
		final CBORFactory f = new CBORFactory();
		final ObjectMapper mapper = new ObjectMapper(f);
		// and then read/write data as usual
		byte[] cborData;
		cborData = mapper.writeValueAsBytes(m);
		// final Message otherValue = mapper.readValue(cborData, Message.class); //
		// check it can be read back
		return cborData;
	}

	// Receive message 2, make and return message 3
	public byte[] createMessage3(byte[] message2) {
		byte[] g_y = message2; // TODO: Decode from message

		PublicKey pk = dh.decodePublicKey(g_y);
		byte[] sharedSecret = dh.generateSecret(keyPair.getPrivate(), pk);
		System.out.println( "Initiator has shared secret " + printHexBinary(sharedSecret));
		return sharedSecret; //message3
	}
}