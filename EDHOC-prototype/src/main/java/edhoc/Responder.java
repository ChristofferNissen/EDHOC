package edhoc;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.KeyPair;

import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.fasterxml.jackson.dataformat.cbor.CBORGenerator;
import com.fasterxml.jackson.dataformat.cbor.CBORParser;

import static javax.xml.bind.DatatypeConverter.printHexBinary;
import static edhoc.Helper.nextByteArray;

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
		
		// Decoding
		CBORParser parser = factory.createParser(message1);
		int methodCorr = parser.nextIntValue(-1);
		int suite = parser.nextIntValue(-1);
		byte[] pk = nextByteArray(parser);
		int c_i = parser.nextIntValue(-1);
		parser.close();

		byte[] sharedSecret = dh.generateSecret(keyPair.getPrivate(), dh.decodePublicKey(pk));
		System.out.println("Responder has shared secret: " + printHexBinary(sharedSecret));

		// Validation
		if (validate1(methodCorr, suite, pk, c_i, sharedSecret) == false) return null;

		// Send response
		System.out.println("Responder public key " + keyPair.getPublic());
		return createMessage2();
	}

	private byte[] createMessage2() throws IOException {
		ByteArrayOutputStream stream = new ByteArrayOutputStream();
		CBORGenerator generator = factory.createGenerator(stream);
		writeData2(generator);
		writeCipherText(generator);
		generator.close();
		return stream.toByteArray();
	}

	// data_2 = (
	//   G_Y : bstr,
	//   C_R : bstr_identifier,
	// )
	private void writeData2(CBORGenerator generator) throws IOException {
		generator.writeBinary(keyPair.getPublic().getEncoded()); 
		generator.writeNumber(c_r);
	}

	private void writeCipherText(CBORGenerator generator) throws IOException {
		// TODO: Create
		generator.writeNull();
	}

	private boolean validate1(int methodCorr, int suite, byte[] pkBytes, int c_i, byte[] sharedSecret) {
		// TODO: More validation
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
		Object cipherText3 = nextCipherText(parser);
		parser.close();

		// Validate
		return validate3(cipherText3);
	}

	private Object nextCipherText(CBORParser parser) {
		// TODO: Create
		return null;
	}

	private boolean validate3(Object cipherText) {
		// TODO: Create
		return false;
	}
}