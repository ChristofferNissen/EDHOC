package edhoc;

import java.math.BigInteger;
import java.util.Random;
import java.io.IOException;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;

import edhoc.model.Message;
import edhoc.model.MessageOne;

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

		Message m = new MessageOne();

		suite = 0; // Some value
		c_i = 0; // Some value
		g_x = dh.power(dh.generator(), privateComponent);
		System.out.println( "Initiator sends " + g_x);
		return 1; //message1
	}

	private byte[] EncodeAsCbor(Message m) throws IOException {
		final CBORFactory f = new CBORFactory();
		final ObjectMapper mapper = new ObjectMapper(f);
		// and then read/write data as usual
		byte[] cborData;
		cborData = mapper.writeValueAsBytes(m);
		// final Message otherValue = mapper.readValue(cborData, Message.class); // check it can be read back
		return cborData;
	}

	// Receive message 2, make and return message 3
	public int createMessage3(final int message2) {
		return 3; //message3
	}
}