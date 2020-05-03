package edhoc;

import java.security.KeyPair;
import java.security.PublicKey;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.fasterxml.jackson.dataformat.cbor.CBORGenerator;
import com.fasterxml.jackson.dataformat.cbor.CBORParser;

import static javax.xml.bind.DatatypeConverter.printHexBinary;
import static edhoc.Helper.nextByteArray;

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
	int method = 0; // Initiator and Responder both use Signature Key
	int corr = 3; // transport provides a correlation mechanism that enables both parties to correlate all three messages
	int suite = 2; // (AES-CCM-16-64-128, SHA-256, P-256, ES256, P-256, AES-CCM-16-64-128, SHA-256)
	int c_i = 5; // bstr / int
	private KeyPair keyPair; // Pair of values for G_X and the private component
	private ECDiffieHellman dh;
	private final CBORFactory factory = new CBORFactory();

	public Initiator(ECDiffieHellman dh) {
		methodCorr = 4 * method + corr;
		this.dh = dh;

		keyPair = dh.generateKeyPair();
		System.out.println("Initiator chooses random value " + printHexBinary(keyPair.getPrivate().getEncoded()));
	}

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
	public byte[] createMessage1() throws IOException {
		// Encode and send
		PublicKey pk = keyPair.getPublic();
		System.out.println("Initiator public key " + pk);

        ByteArrayOutputStream stream = new ByteArrayOutputStream();
		CBORGenerator generator = factory.createGenerator(stream);
		generator.writeNumber(methodCorr);
		generator.writeNumber(suite);
		generator.writeBinary(pk.getEncoded());
		generator.writeNumber(c_i);
		generator.close();
		
		return stream.toByteArray();
	}

	// Receive message 2, make and return message 3
	public byte[] createMessage3(byte[] message2) throws IOException {
		// Decoding
		CBORParser parser = factory.createParser(message2);
		byte[] pk = nextByteArray(parser);
		int c_r = parser.nextIntValue(-1);
		Object cipherText = nextCipherText2(parser);
		parser.close();

		byte[] sharedSecret = dh.generateSecret(keyPair.getPrivate(), dh.decodePublicKey(pk));
		System.out.println("Initiator has shared secret: " + printHexBinary(sharedSecret));

		// Validation
		if (validate(pk, c_r, cipherText) == false) return null;
	
		return createMessage3();
	}

	// message_3 = (
	// 	CIPHERTEXT_3 : bstr,
	// )
	private byte[] createMessage3() throws IOException {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
		CBORGenerator generator = factory.createGenerator(stream);
		writeCipherText3(generator);
		generator.close();
		return stream.toByteArray();
	}

	private boolean validate(byte[] pk, int c_r, Object cipherText) {
		// TODO: validate
		boolean isInvalid = c_r == -1 || pk == null;
		if (isInvalid) {
			System.out.println("Validation failed: Aborting.");
		}
		return !isInvalid;
	}

	private void writeCipherText3(CBORGenerator generator) throws IOException {
		// TODO: create
		generator.writeNull();
	}

	private Object nextCipherText2(CBORParser parser) {
		// TODO: create
		return null;
	}

}