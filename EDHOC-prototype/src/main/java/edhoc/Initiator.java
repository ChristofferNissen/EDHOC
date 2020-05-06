package edhoc;

import java.security.KeyPair;
import java.security.PublicKey;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.fasterxml.jackson.dataformat.cbor.CBORGenerator;
import com.fasterxml.jackson.dataformat.cbor.CBORParser;
import com.upokecenter.cbor.CBORObject;

import COSE.AlgorithmID;
import COSE.Attribute;
import COSE.CoseException;
import COSE.HeaderKeys;
import COSE.OneKey;
import COSE.Sign1Message;

import static javax.xml.bind.DatatypeConverter.printHexBinary;
import static edhoc.Helper.*;

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

	byte[] ID_CRED_R = new byte[]{0x14};
	byte[] ID_CRED_I = new byte[]{0x23};
	private KeyPair keyPair; // Pair of values for G_X and the private component
	private ECDiffieHellman dh;
	private final CBORFactory factory = new CBORFactory();
	byte[] G_XY = null;
	byte[] message1 = null;
	KeyPair signatureKeyPair;
	PublicKey responderPk;
	public Initiator(ECDiffieHellman dh, KeyPair signatureKeyPair, PublicKey responderPk) {
		methodCorr = 4 * method + corr;
		this.dh = dh;
		this.signatureKeyPair = signatureKeyPair;
		this.responderPk = responderPk;
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

		message1 = stream.toByteArray();
		
		return message1;
	}

	// Receive message 2, make and return message 3
	public byte[] createMessage3(byte[] message2) throws IOException, CoseException{
		// Decoding
		CBORParser parser = factory.createParser(message2);
		byte[] pk = nextByteArray(parser);
		int c_r = parser.nextIntValue(-1);
		byte[] CIPHERTEXT_2 = nextByteArray(parser);
		parser.close();

		G_XY = dh.generateSecret(keyPair.getPrivate(), dh.decodePublicKey(pk));
		System.out.println("Initiator has shared secret: " + printHexBinary(G_XY));
		
		byte[] data2 = createData2(c_r, pk);
		byte[] TH_2 = SHA256(concat(message1, data2));
		byte[] PRK_2e = HMAC_SHA256(G_XY, new byte[0]); // Salt is empty since we authenticate using asymmetric keys

		byte[] K_2e_info = makeInfo("XOR-ENCRYPTION", CIPHERTEXT_2.length, TH_2);
		byte[] K_2e = hkdf(CIPHERTEXT_2.length, PRK_2e, new byte[0], K_2e_info);

		byte[] plaintext = xor(K_2e, CIPHERTEXT_2);

		System.out.println("Initiator has plaintext = " + printHexBinary(plaintext) );

		System.out.println("Correctly identified the other party: " + (plaintext[0] == ID_CRED_R[0]) );
		byte[] CRED_R = responderPk.getEncoded();
		System.out.println("Initator connects " + printHexBinary(ID_CRED_R) + " to key " + printHexBinary(CRED_R));

		byte[] signature = new byte[plaintext.length-1];
		for (int i = 1; i < plaintext.length; ++i) {
			signature[i-1] = plaintext[i];
		}

		Sign1Message M = (Sign1Message) Sign1Message.DecodeFromBytes(signature);
		M.addAttribute(HeaderKeys.Algorithm, AlgorithmID.ECDSA_256.AsCBOR(), Attribute.DO_NOT_SEND); // ES256 over the curve P-256

		byte[] external = concat(TH_2, CRED_R);
		M.setExternal( external ); // external_aad = << TH_2, CRED_R >>

		System.out.println( "External data = " + printHexBinary(external));
		System.out.println( "Received signature = " + printHexBinary(signature));
		System.out.println( "Signature is valid: " + M.validate(new OneKey(responderPk, null)) );
		

		byte[] TH_3 = SHA256(concat(TH_2, CIPHERTEXT_2));


		// Validation
		if (validate(pk, c_r, CIPHERTEXT_2) == false) return null;
	
		return createMessage3();	
	}

	private byte[] createData2(int c_r, byte[] pk) throws IOException {
		ByteArrayOutputStream stream = new ByteArrayOutputStream();
		CBORGenerator generator = factory.createGenerator(stream);
		generator.writeBinary(pk);
		generator.writeNumber(c_r);
		generator.close();
		return stream.toByteArray();
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