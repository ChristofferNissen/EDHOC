package edhoc;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.PublicKey;

import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.fasterxml.jackson.dataformat.cbor.CBORGenerator;
import com.fasterxml.jackson.dataformat.cbor.CBORParser;
import com.upokecenter.cbor.CBORObject;

import COSE.AlgorithmID;
import COSE.Attribute;
import COSE.CoseException;
import COSE.Encrypt0Message;
import COSE.HeaderKeys;
import COSE.OneKey;
import COSE.Sign1Message;

import static javax.xml.bind.DatatypeConverter.printHexBinary;
import static edhoc.Helper.*;

public class Responder {
	private static final CBORFactory factory = new CBORFactory();
	int c_r;
	KeyPair keyPair;
	ECDiffieHellman dh;
	byte[] G_XY;

	byte[] ID_CRED_R = new byte[]{0x14};
	byte[] ID_CRED_I = new byte[]{0x23};

	KeyPair signatureKeyPair;
	byte[] CRED_R;
	PublicKey initiatorPk;

	public Responder(ECDiffieHellman dh, KeyPair signatureKeyPair, PublicKey initiatorPk){
		c_r = 7; // Some perfectly random value
		keyPair = dh.generateKeyPair();
		System.out.println("Responder chooses random value " + printHexBinary(keyPair.getPrivate().getEncoded()));
		this.dh = dh;
		this.signatureKeyPair = signatureKeyPair;
		this.initiatorPk = initiatorPk;
		this.CRED_R = signatureKeyPair.getPublic().getEncoded();
	}

	// message_2 = (
	// data_2,
	// CIPHERTEXT_2 : bstr,
	// )
	// validate message 1
	// The Responder SHALL process message_1 as follows:
	// Decode message_1 (see Appendix A.1).
	// Verify that the selected cipher suite is supported and that no prior cipher
	// suites in SUITES_I are supported.
	// Pass AD_1 to the security application.
	// send response
	public byte[] createMessage2(byte[] message1) throws IOException, CoseException {
		// Decoding
		CBORParser parser = factory.createParser(message1);
		int methodCorr = parser.nextIntValue(-1);
		int suite = parser.nextIntValue(-1);
		byte[] pk = nextByteArray(parser);
		int c_i = parser.nextIntValue(-1);
		parser.close();

		G_XY = dh.generateSecret(keyPair.getPrivate(), dh.decodePublicKey(pk));
		System.out.println("Responder has shared secret: " + printHexBinary(G_XY));


		if (validate1(methodCorr, suite, pk, c_i, G_XY) == false)
			return null;

		System.out.println("Responder public key " + keyPair.getPublic());

		byte[] data2 = createData2();
		byte[] cipherText2 = createCipherText2(message1, data2);

		return concat(data2, cipherText2);
	}

	// data_2 = (
	// G_Y : bstr,
	// C_R : bstr_identifier,
	// )
	private byte[] createData2() throws IOException {
		ByteArrayOutputStream stream = new ByteArrayOutputStream();
		CBORGenerator generator = factory.createGenerator(stream);
		generator.writeBinary(keyPair.getPublic().getEncoded());
		generator.writeNumber(c_r);
		generator.close();
		return stream.toByteArray();
	}

	private byte[] createCipherText2(byte[] message1, byte[] data2) throws IOException, CoseException {
		byte[] TH_2 = SHA256(concat(message1, data2));
		byte[] PRK_2e = HMAC_SHA256(G_XY, new byte[0]); // Salt is empty since we authenticate using asymmetric keys
		byte[] PRK_3e2m = PRK_2e; // Since responder doesn't authenticate with a static DH key. 
		int L = 64; // Since we use cipher suite 2
		int IV_L = L / 8;
		int K_2m_L = L / 4;

		Encrypt0Message msg = new Encrypt0Message();
		msg.addAttribute(HeaderKeys.Algorithm, AlgorithmID.AES_CCM_16_64_128.AsCBOR(), Attribute.DO_NOT_SEND);
		msg.addAttribute(HeaderKeys.KID, CBORObject.FromObject(ID_CRED_R), Attribute.PROTECTED); // protected = << ID_CRED_R >>
		msg.setExternal( concat(TH_2, keyPair.getPrivate().getEncoded()) ); // external_aad = << TH_2, CRED_R >>
		msg.SetContent(""); // plaintext = h''

		byte[] IV_2m_info = makeInfo("IV-GENERATION", IV_L, TH_2);
		byte[] IV_2m = hkdf(IV_L, PRK_3e2m, new byte[0], IV_2m_info);
		msg.addAttribute(HeaderKeys.IV, IV_2m, Attribute.DO_NOT_SEND);

		byte algorithmID = 10; // 10 refers to our algorithm AES_CCM_16_64_128(__10__, 128, 64),
		byte[] K_2m_info = makeInfo(new byte[]{algorithmID}, K_2m_L, TH_2, msg.getProtectedAttributes().EncodeToBytes()); 
		byte[] K_2m = hkdf(K_2m_L, PRK_2e, new byte[0], K_2m_info);
		msg.encrypt(K_2m);

		byte[] MAC_2 = msg.EncodeToBytes();

		System.out.println("msg encoded = " + printHexBinary(MAC_2) );


		Sign1Message M = new Sign1Message();
		M.addAttribute(HeaderKeys.Algorithm, AlgorithmID.ECDSA_256.AsCBOR(), Attribute.DO_NOT_SEND); // ES256 over the curve P-256
		
		// protected = << ID_CRED_R >>
		M.addAttribute(HeaderKeys.KID, CBORObject.FromObject(ID_CRED_R), Attribute.PROTECTED); // protected = << ID_CRED_R >>
		byte[] external = concat(TH_2, CRED_R);
		M.setExternal( external ); // external_aad = << TH_2, CRED_R >>
		M.SetContent(MAC_2); // payload

		OneKey key = new OneKey(signatureKeyPair.getPublic(), signatureKeyPair.getPrivate());
		M.sign(key);


		byte[] signature = M.EncodeToBytes();
		byte[] plaintext = concat(ID_CRED_R, signature);

		System.out.println( "External data = " + printHexBinary(external));
		System.out.println( "Responder signature = " + printHexBinary(signature));
		System.out.println("Responder has plaintext = " + printHexBinary(plaintext) );

		byte[] K_2e_info = makeInfo("XOR-ENCRYPTION", plaintext.length, TH_2);
		byte[] K_2e = hkdf(plaintext.length, PRK_2e, new byte[0], K_2e_info);

		byte[] ciphertext = xor(K_2e, plaintext);

        ByteArrayOutputStream stream = new ByteArrayOutputStream();
		CBORGenerator generator = factory.createGenerator(stream);
		generator.writeBinary(ciphertext);
		generator.close();

		return stream.toByteArray();
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