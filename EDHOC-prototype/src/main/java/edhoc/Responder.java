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

	int C_R; // bstr / int
	ECDiffieHellman dh;
	PublicKey G_Y;
	byte[] G_XY;
	byte[] ID_CRED_R = new byte[]{0x14};
	byte[] ID_CRED_I = new byte[]{0x23};
	byte[] CRED_R;
	byte[] CRED_I;
	byte[] CIPHERTEXT_2 = null;
	byte[] TH_2 = null;
	KeyPair keyPair; // Pair of values for G_Y and the private component
	OneKey signatureKey;
	OneKey verificationKey;

	public Responder(ECDiffieHellman dh, KeyPair signatureKeyPair, PublicKey initiatorPk) throws CoseException {
		C_R = 7; // Some perfectly random value
		keyPair = dh.generateKeyPair();
		G_Y = keyPair.getPublic();
		System.out.println("Setting up Responder before protocol...");
		System.out.println("Responder chooses random value " + printHexBinary(keyPair.getPrivate().getEncoded()) + "\n");
		this.dh = dh;
		signatureKey = new OneKey(signatureKeyPair.getPublic(), signatureKeyPair.getPrivate());
		verificationKey = new OneKey(initiatorPk, null);
		CRED_R = signatureKeyPair.getPublic().getEncoded();
		CRED_I = initiatorPk.getEncoded();
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
		System.out.println("	Cipher suite(" + suite +") supported..");
		System.out.println("	[SKIPPED] Pass AD_1 to the security application\n");

		System.out.println("Responder Processing of Message 2\n");

		System.out.println("Responder public key " + G_Y);

		G_XY = dh.generateSecret(keyPair.getPrivate(), dh.decodePublicKey(pk));
		System.out.println("Responder has shared secret: " + printHexBinary(G_XY));

		byte[] data2 = createData2(G_Y, C_R);
		byte[] cipherText2 = createCIPHERTEXT_2(message1, data2);
		return concat(data2, cipherText2);
	}

	// data_2 = (
	// G_Y : bstr,
	// C_R : bstr_identifier,
	// )

	private byte[] createCIPHERTEXT_2(byte[] message1, byte[] data2) throws IOException, CoseException {
		TH_2 = SHA256(concat(message1, data2));

		// Used to derive key and IV to encrypt message_2
		byte[] PRK_2e = HMAC_SHA256(G_XY);
		// Used to derive keys and produce a mac in message_2
		byte[] PRK_3e2m = PRK_2e; // Since responder doesn't authenticate with a static DH key. 

		// Start of inner COSE_Encrypt0 creation
		Encrypt0Message inner = new Encrypt0Message();
		inner.addAttribute(HeaderKeys.Algorithm, AlgorithmID.AES_CCM_16_64_128.AsCBOR(), Attribute.DO_NOT_SEND);
		inner.addAttribute(HeaderKeys.KID, CBORObject.FromObject(ID_CRED_R), Attribute.PROTECTED); // protected = << ID_CRED_R >>
		inner.setExternal( concat(TH_2, keyPair.getPrivate().getEncoded()) ); // external_aad = << TH_2, CRED_R >>
		inner.SetContent(""); // plaintext = h''

		byte[] K_2m = makeK_2m(PRK_3e2m, inner.getProtectedAttributes(), TH_2);
		byte[] IV_2m = makeIV_2m(PRK_3e2m, inner.getProtectedAttributes(), TH_2);
		inner.addAttribute(HeaderKeys.IV, CBORObject.FromObject(IV_2m), Attribute.DO_NOT_SEND);
		inner.encrypt(K_2m);

		byte[] MAC_2 = inner.EncodeToBytes(); 

		System.out.println("msg encoded = " + printHexBinary(MAC_2) );
		// Inner COSE_Encrypt0 created

		// Start of COSE_Sign1 creation
		Sign1Message M = new Sign1Message();
		M.addAttribute(HeaderKeys.Algorithm, AlgorithmID.ECDSA_256.AsCBOR(), Attribute.DO_NOT_SEND); // ES256 over the curve P-256
		M.addAttribute(HeaderKeys.KID, CBORObject.FromObject(ID_CRED_R), Attribute.PROTECTED); // protected = << ID_CRED_R >>
		M.setExternal( concat(TH_2, CRED_R) ); // external_aad = << TH_2, CRED_R >>
		M.SetContent(MAC_2); // payload
		M.sign(signatureKey);

		byte[] signature = M.EncodeToBytes();
		// Signature created

		byte[] plaintext = concat(ID_CRED_R, signature);

		System.out.println( "Responder signature = " + printHexBinary(signature) );
		System.out.println( "Responder has plaintext = " + printHexBinary(plaintext) );

		byte[] K_2e = makeK_2e(PRK_2e, TH_2, plaintext.length);

		CIPHERTEXT_2 = xor(K_2e, plaintext); // Enc(K_2e; ID_CRED_R, Signature_or_MAC_2, AD_2)
		return encodeToCBOR(CIPHERTEXT_2);
	}

	private byte[] encodeToCBOR(byte[] bytes) throws IOException {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
		CBORGenerator generator = factory.createGenerator(stream);
		generator.writeBinary(bytes);
		generator.close();
		return stream.toByteArray();
	}

	private byte[] makeK_2m(byte[] PRK_3e2m, CBORObject protectedAttributes, byte[] tH_22) {
		byte[] K_2m_info = makeInfo(new byte[]{AEAD_ALGORITHM_ID}, AEAD_KEY_LENGTH, protectedAttributes.EncodeToBytes(), TH_2); 
		return hkdf(AEAD_KEY_LENGTH, PRK_3e2m, K_2m_info);
	}

	private byte[] makeIV_2m(byte[] PRK_3e2m, CBORObject protectedAttr, byte[] TH_2) {
		byte[] COSE_Encrypt0_protected = protectedAttr.EncodeToBytes();
		byte[] IV_2m_info = makeInfo("IV-GENERATION", AES_CCM_16_IV_LENGTH, COSE_Encrypt0_protected, TH_2);
		return hkdf(AES_CCM_16_IV_LENGTH, PRK_3e2m, IV_2m_info);
	}
	// Receive message 3, return valid boolean
	public boolean validateMessage3(byte[] message3) throws IOException, CoseException {
		System.out.println("Responder Processing of Message 3\n");

		// Decoding

		byte[] TH_3 = SHA256(concat(TH_2, CIPHERTEXT_2));
		byte[] PRK_3e2m = HMAC_SHA256(G_XY);

		byte[] CIPHERTEXT_3 = readCIPHERTEXT_3(message3);		

		Encrypt0Message outer_encrypt0 = (Encrypt0Message) Encrypt0Message.DecodeFromBytes(CIPHERTEXT_3);
		outer_encrypt0.addAttribute(HeaderKeys.Algorithm, AlgorithmID.AES_CCM_16_64_128.AsCBOR(), Attribute.DO_NOT_SEND); // AEAD Algorithm
		outer_encrypt0.setExternal(TH_3);

		byte[] IV_3ae = makeIV_3ae(PRK_3e2m, outer_encrypt0.getProtectedAttributes(), TH_3);
		outer_encrypt0.addAttribute(HeaderKeys.IV, CBORObject.FromObject(IV_3ae), Attribute.DO_NOT_SEND);

		byte[] K_3ae = makeK_3ae(PRK_3e2m, outer_encrypt0.getProtectedAttributes(), TH_3);
		byte[] plaintext = outer_encrypt0.decrypt(K_3ae);

		System.out.println( "Responder K_3ae = " + printHexBinary(K_3ae) );
		System.out.println( "Responder gets plaintext = " + printHexBinary(plaintext) );
		System.out.println("Correctly identified the other party: " + (plaintext[0] == ID_CRED_I[0]) );
		System.out.println("Responder connects " + printHexBinary(ID_CRED_I) + " to key " + printHexBinary(CRED_I));

		Sign1Message M = (Sign1Message) Sign1Message.DecodeFromBytes(readSignature(plaintext));
		M.addAttribute(HeaderKeys.Algorithm, AlgorithmID.ECDSA_256.AsCBOR(), Attribute.DO_NOT_SEND); // ES256 over the curve P-256
		M.setExternal( concat(TH_3, CRED_I) ); // external_aad = << TH_2, CRED_R >>

		boolean result = M.validate(verificationKey);
		System.out.println( "Signature is valid: " + result + "\n" );

		return result;
	}

	private byte[] readCIPHERTEXT_3(byte[] message3) throws IOException {
		CBORParser parser = factory.createParser(message3);
		byte[] array = nextByteArray(parser);
		parser.close();
		return array;
	}

}
