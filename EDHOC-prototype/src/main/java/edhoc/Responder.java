package edhoc;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.KeyPair;

import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.fasterxml.jackson.dataformat.cbor.CBORGenerator;
import com.fasterxml.jackson.dataformat.cbor.CBORParser;

import static javax.xml.bind.DatatypeConverter.printHexBinary;
import static edhoc.Helper.*;

public class Responder {
	private static final CBORFactory factory = new CBORFactory();
	int c_r;
	KeyPair keyPair;
	ECDiffieHellman dh;

	public Responder(ECDiffieHellman dh) {
		c_r = 7; // Some perfectly random value 
		keyPair = dh.generateKeyPair();
		System.out.println("Responder chooses random value " + printHexBinary(keyPair.getPrivate().getEncoded()));
		this.dh = dh;
	}

	// message_2 = (
	// 	data_2,
	// 	CIPHERTEXT_2 : bstr,
	// )
	// validate message 1
	// The Responder SHALL process message_1 as follows:
	// Decode message_1 (see Appendix A.1).
	// Verify that the selected cipher suite is supported and that no prior cipher
	// suites in SUITES_I are supported.
	// Pass AD_1 to the security application.
	// send response
	public byte[] createMessage2(byte[] message1) throws IOException {

		// Responder Processing of Message 1

		// Decode message_1 (see Appendix A.1)
		CBORParser parser = factory.createParser(message1);
		int methodCorr = parser.nextIntValue(-1); 	// int
		int suite = parser.nextIntValue(-1);		// int
		byte[] pk = nextByteArray(parser);			// bstr
		int c_i = parser.nextIntValue(-1);			// bstr_identifier
		parser.close();

		// Verify the selected cipher suite is supported and that no prior cipher suites in SUITES_I are supported.
		// Skipped

		// PASS AD_1 to the security application
		// Skipped

		System.out.println("Responder processed message._1");



		// Responder Processing of Message 2
		System.out.println("Responder processing message._2");

		// If corr (METHOD_CORR mod 4) equals 1 or 3, c_I is omitted, otherwise C_I is not omitted.
		// boolean omitCI = methodCorr % 4 == 1 || methodCorr % 4 == 3; 

		// Generate an ephemeral ECDH key pair as specified in Section 5 of [SP-800-56A] using 
		// the curve in the selected cipher suite and format it as a COSE_Key.
		// Let G_Y be the 'x' parameter of the COSE_Key.
		// Done in constructor
		
		// Choose a connection identifier C_R and store it for the length of the protocol
		// Done in constructor: class variable c_r = 7


		// When using a static Diffie-Hellmann key the authentication is provided by a Message 
		// Authentication code (MAC) computed from an emphemeral-static ECDH shared secret which
		// enables significant reductions in message sizes. The MAC is implemented with an AEAD 
		// algorithm.

		byte[] sharedSecret = dh.generateSecret(keyPair.getPrivate(), dh.decodePublicKey(pk));
		System.out.println("Responder has shared secret: " + printHexBinary(sharedSecret));
		
        byte[] hmac = HMAC_SHA256(new byte[0], sharedSecret);
		System.out.println("Responder hmac: " + printHexBinary(hmac));


		if (validate1(methodCorr, suite, pk, c_i, sharedSecret) == false) return null;

		System.out.println("Responder public key " + keyPair.getPublic());


		// Compute the transcript hash TH_2 = H(message_1, data_2) where H() is the hash function
		// in the selected cipher suite. The transcript hash TH_2 is a CBOR encoded bstr and 
		// the input to the hash function is a CBOR Sequence.
		// suite 2: hash function = SHA-256
	
		// byte[] th2 = sha256Hashing(concat(message1, data2)); 


			
		// Compute an inner COSE_Encrypt0 as defined in Section 5.3 of [RFC8152], with 
		// the EDHOC AEAD algorithm in the selected cipher suite, K_2m, IV_2m and the following parameters:
			// - protected = <<ID_CRED_R>>
			// - external_aad = <<TH_2, CRED_R, ? AD_2 >>
			// - plaintext = h'' (empty bstr)

			// COSE constructs the input to the AEAD [RFC5116] as follows
			// Key K = K_2m
			// Nonce N = IV_2m
			// Plaintext P = 0x (the empty string)
			// Associated data A = ["Encrypt0", <<ID_CRED_R>>,<<TH_2, CRED_R, ? AD_2 >>]

			// MAC_2 is the 'ciphertext' of the inner COSE_Encrypt0
		
		// If the Responder authenticates with a static Diffie-Hellman key (method equals 1 or 3),
		// then Signature_or_MAC_2 is MAC_2.

		// CIPHERTEXT_2 is the ciphertext resulting from XOR encrypting a plaintext with 
		// the following common parameters: 
			// plaintext = (ID_CRED_R / bstr_identifier, Signature_or_MAC_2, ? AD_2)
	
			// CIPHERTEXT_2 = plaintext XOR K_2e
				// The key K_2e is derived using the pseudorandom key PRK_2e, 
				// AlgorithmID = "XOR-ENCRYPTION", keyDataLength = plaintext length, 
				// protected = h''(empty bstr) and other = TH_2 

		byte[] data2 = createData2();
		byte[] cipherText2 = createCipherText2(message1, data2);




		// Example encryption remove
		System.out.println("Data2 length: " + data2.length);
		byte[] th2 = new byte[]{};
		byte[] hkdfKey = hkdf(data2.length, hmac, makeInfo("XOR-ALGORITHM", data2.length, th2), new byte[0]);
		System.out.println( "Encrypted data2: " + printHexBinary(xor(hkdfKey, data2)) );



		// Encode message_2 as a sequence of CBOR encoded data items as specified in Section 4.3.1.
		return concat(data2, cipherText2);

	}

	// data_2 = (
	//   G_Y : bstr,
	//   C_R : bstr_identifier,
	// )
	private byte[] createData2() throws IOException {
		ByteArrayOutputStream stream = new ByteArrayOutputStream();
		CBORGenerator generator = factory.createGenerator(stream);
		generator.writeBinary(keyPair.getPublic().getEncoded()); 
		generator.writeNumber(c_r);
		generator.close();
		return stream.toByteArray();
	}

	private byte[] createCipherText2(byte[] message1, byte[] data2) throws IOException {
		ByteArrayOutputStream stream = new ByteArrayOutputStream();
		CBORGenerator generator = factory.createGenerator(stream);

		byte[] th2 = sha256Hashing(concat(message1, data2)); // Temporary, replace with correct signature
		
		generator.writeBinary(th2); 
		generator.close();
		return stream.toByteArray();

	}

	private boolean validate1(int methodCorr, int suite, byte[] pkBytes, int c_i, byte[] sharedSecret) {
		boolean isInvalid = methodCorr == -1 || suite == -1 || c_i == -1;

		if (isInvalid) {
			System.out.println("Validation failed: Aborting.");
		}

		return !isInvalid;
	}

	// Receive message 3, return valid boolean
	public boolean validateMessage3(byte[] message3) throws IOException {
		// Decode
		CBORParser parser = factory.createParser(message3);
		Object cipherText3 = nextCipherText3(parser);
		parser.close();

		// Validate
		return validate3(cipherText3);
	}

	private Object nextCipherText3(CBORParser parser) {
		// TODO: Create
		return null;
	}

	private boolean validate3(Object cipherText) {
		// TODO: Create
		return false;
	}
}