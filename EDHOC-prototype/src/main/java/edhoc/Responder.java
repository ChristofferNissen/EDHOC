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

	byte[] CIPHERTEXT_2 = null;
	byte[] TH_2 = null;
	KeyPair signatureKeyPair;
	byte[] CRED_R;
	PublicKey initiatorPk;

	public Responder(ECDiffieHellman dh, KeyPair signatureKeyPair, PublicKey initiatorPk){
		c_r = 7; // Some perfectly random value
		keyPair = dh.generateKeyPair();
		System.out.println("Setting up Responder before protocol...");
		System.out.println("Responder chooses random value " + printHexBinary(keyPair.getPrivate().getEncoded()) + "\n");
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
		System.out.println("Responder Processing of Message 1\n");
		// Decoding
		CBORParser parser = factory.createParser(message1);
		int methodCorr = parser.nextIntValue(-1);
		int suite = parser.nextIntValue(-1);
		byte[] pk = nextByteArray(parser);
		int c_i = parser.nextIntValue(-1);
		parser.close();

		System.out.println("	Decoded message one successfully..");
		System.out.println("	Cipher suite supported..");
		System.out.println("	[SKIPPED] Pass AD_1 to the security application\n");

		System.out.println("Responder Processing of Message 2\n");

		System.out.println("Responder public key " + keyPair.getPublic());

		G_XY = dh.generateSecret(keyPair.getPrivate(), dh.decodePublicKey(pk));
		System.out.println("Responder has shared secret: " + printHexBinary(G_XY));

		if (validate1(methodCorr, suite, pk, c_i, G_XY) == false)
			return null;

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
		TH_2 = SHA256(concat(message1, data2));

		// Used to derive key and IV to encrypt message_2
		byte[] PRK_2e = HMAC_SHA256(G_XY);
		// Used to derive keys and produce a mac in message_2
		byte[] PRK_3e2m = PRK_2e; // Since responder doesn't authenticate with a static DH key. 
		int L = 64; // Since we use cipher suite 2
		int IV_L = L / 8;
		int K_2m_L = L / 4;

		Encrypt0Message msg = new Encrypt0Message();
		msg.addAttribute(HeaderKeys.Algorithm, AlgorithmID.AES_CCM_16_64_128.AsCBOR(), Attribute.DO_NOT_SEND);
		msg.addAttribute(HeaderKeys.KID, CBORObject.FromObject(ID_CRED_R), Attribute.PROTECTED); // protected = << ID_CRED_R >>
		msg.setExternal( concat(TH_2, keyPair.getPrivate().getEncoded()) ); // external_aad = << TH_2, CRED_R >>
		msg.SetContent(""); // plaintext = h''

		byte[] COSE_Encrypt0_protected = msg.getProtectedAttributes().EncodeToBytes();
		byte[] IV_2m_info = makeInfo("IV-GENERATION", IV_L, COSE_Encrypt0_protected, TH_2);
		byte[] IV_2m = hkdf(IV_L, PRK_3e2m, new byte[0], IV_2m_info);
		msg.addAttribute(HeaderKeys.IV, CBORObject.FromObject(IV_2m), Attribute.DO_NOT_SEND);

		byte algorithmID = 10; // 10 refers to our algorithm AES_CCM_16_64_128(__10__, 128, 64),
		byte[] K_2m_info = makeInfo(new byte[]{algorithmID}, K_2m_L, COSE_Encrypt0_protected, TH_2); 
		byte[] K_2m = hkdf(K_2m_L, PRK_3e2m, new byte[0], K_2m_info);
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

		CIPHERTEXT_2 = xor(K_2e, plaintext);

        ByteArrayOutputStream stream = new ByteArrayOutputStream();
		CBORGenerator generator = factory.createGenerator(stream);
		generator.writeBinary(CIPHERTEXT_2);
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

	public static final int AES_CCM_16_IV_LENGTH = 13;

	// Receive message 3, return valid boolean
	public boolean validateMessage3(byte[] message3) throws IOException, CoseException {
		System.out.println("Responder Processing of Message 3\n");

		// Decoding
		CBORParser parser = factory.createParser(message3);
		byte[] CIPHERTEXT_3 = nextByteArray(parser);
		parser.close();

		byte algorithmID = 10;
		int L = 64; // Since we use cipher suite 2
		int K_L = L / 4;

		Encrypt0Message outer_encrypt0 = (Encrypt0Message) Encrypt0Message.DecodeFromBytes(CIPHERTEXT_3);
		outer_encrypt0.addAttribute(HeaderKeys.Algorithm, AlgorithmID.AES_CCM_16_64_128.AsCBOR(), Attribute.DO_NOT_SEND); // AEAD Algorithm
		
		byte[] TH_3 = SHA256(concat(TH_2, CIPHERTEXT_2));
		byte[] PRK_3e2m = HMAC_SHA256(G_XY);

		outer_encrypt0.setExternal(TH_3);

		System.out.println( AlgorithmID.AES_CCM_16_64_128.getTagSize() );

		byte[] IV_3ae_info = makeInfo("IV-GENERATION", AES_CCM_16_IV_LENGTH, outer_encrypt0.getProtectedAttributes().EncodeToBytes(), TH_3);
		byte[] IV_3ae = hkdf(AES_CCM_16_IV_LENGTH, PRK_3e2m, new byte[0], IV_3ae_info);

		outer_encrypt0.addAttribute(HeaderKeys.IV, CBORObject.FromObject(IV_3ae), Attribute.DO_NOT_SEND);

		byte[] K_3ae_info = makeInfo(new byte[]{algorithmID}, K_L, outer_encrypt0.getProtectedAttributes().EncodeToBytes(), TH_3);
		byte[] K_3ae = hkdf(K_L, PRK_3e2m, new byte[0], K_3ae_info);

		System.out.println( "Responder K_3ae = " + printHexBinary(K_3ae) );

		byte[] plaintext = outer_encrypt0.decrypt(K_3ae);

		System.out.println( "Responder gets plaintext = " + printHexBinary(plaintext) );

		System.out.println("Correctly identified the other party: " + (plaintext[0] == ID_CRED_I[0]) );
		byte[] CRED_R = initiatorPk.getEncoded();
		System.out.println("Responder connects " + printHexBinary(ID_CRED_I) + " to key " + printHexBinary(CRED_R));

		byte[] signature = new byte[plaintext.length-1];
		for (int i = 1; i < plaintext.length; ++i) {
			signature[i-1] = plaintext[i];
		}

		Sign1Message M = (Sign1Message) Sign1Message.DecodeFromBytes(signature);
		M.addAttribute(HeaderKeys.Algorithm, AlgorithmID.ECDSA_256.AsCBOR(), Attribute.DO_NOT_SEND); // ES256 over the curve P-256

		byte[] CRED_I = initiatorPk.getEncoded();
		byte[] external = concat(TH_3, CRED_I);
		M.setExternal( external ); // external_aad = << TH_2, CRED_R >>

		System.out.println( "External data = " + printHexBinary(external));
		System.out.println( "Received signature = " + printHexBinary(signature));
		System.out.println( "Signature is valid: " + M.validate(new OneKey(initiatorPk, null)) + "\n" );

		return true;
	}

}
