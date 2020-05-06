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
import COSE.Encrypt0Message;
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

	public static final int AES_CCM_16_IV_LENGTH = 13;
	byte[] CRED_I;
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
		CRED_I = signatureKeyPair.getPublic().getEncoded();
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
		
		// processing of message_2 done


		// processing of message_3 start

		// Used to encrypt message_3
		byte[] PRK_3e2m = PRK_2e; // Since we don't use static Diffie-Hellman key
		// Used to derive keys and IVs to produce a MAC in message_3 and to
		// derive application specific data
		byte[] PRK_4x3m = PRK_3e2m; // Since we don't use static Diffie-Hellman key

		int L = 64; // Since we use cipher suite 2
		int K_L = L / 4;

		byte[] TH_3 = SHA256(concat(TH_2, CIPHERTEXT_2));
		// Compute an inner COSE_Encrypt0 as defined in Section 5.3 of [RFC8152], with
		// the EDHOC AEAD algorithm in the selected cipher suite, K_3m IV_3m and the 
		// following parameters: (Omitted)
		// MAC_3 is the 'ciphertext' of the inner COSE_Encrypt0.

		Encrypt0Message inner = new Encrypt0Message();
		inner.addAttribute(HeaderKeys.Algorithm, AlgorithmID.AES_CCM_16_64_128.AsCBOR(), Attribute.DO_NOT_SEND);
		inner.addAttribute(HeaderKeys.KID, CBORObject.FromObject(ID_CRED_I), Attribute.PROTECTED); // protected = << ID_CRED_R >>
		inner.setExternal( concat(TH_3, CRED_I) ); // external_aad = << TH_3, CRED_I >>
		inner.SetContent(""); // plaintext = h''

		// Nonce N = IV_3m is th output of HKDF-Expand(PRK_4x3m, info, L)	
		byte[] COSE_Encrypt0_protected = inner.getProtectedAttributes().EncodeToBytes();
		byte[] IV_3m_info = makeInfo("IV-GENERATION", AES_CCM_16_IV_LENGTH, COSE_Encrypt0_protected, TH_3);
		byte[] IV_3m = hkdf(AES_CCM_16_IV_LENGTH, PRK_4x3m, new byte[0], IV_3m_info);
		inner.addAttribute(HeaderKeys.IV, IV_3m, Attribute.DO_NOT_SEND);

		// K_3m s
		byte algorithmID = 10; // 10 refers to our algorithm AES_CCM_16_64_128(__10__, 128, 64),
		byte[] K_3m_info = makeInfo(new byte[]{algorithmID}, K_L, COSE_Encrypt0_protected, TH_3); 
		byte[] K_3m = hkdf(K_L, PRK_4x3m, new byte[0], K_3m_info);
		inner.encrypt(K_3m);

		// If the Initiator authenticates with a static Diffie-Hellman key (method equals 2 or 3)
		// then the Signature_or_MAC_3 is MAC_3.
		byte[] MAC_3 = inner.EncodeToBytes();

		System.out.println("msg encoded = " + printHexBinary(MAC_3) );

		M = new Sign1Message();
		M.addAttribute(HeaderKeys.Algorithm, AlgorithmID.ECDSA_256.AsCBOR(), Attribute.DO_NOT_SEND); // ES256 over the curve P-256
		
		M.addAttribute(HeaderKeys.KID, CBORObject.FromObject(ID_CRED_I), Attribute.PROTECTED); // protected = << ID_CRED_I >>
		M.setExternal( concat(TH_3, CRED_I) ); // << TH_3, CRED_I >>
		M.SetContent(MAC_3); // payload

		OneKey key = new OneKey(signatureKeyPair.getPublic(), signatureKeyPair.getPrivate());
		M.sign(key);

		signature = M.EncodeToBytes();

		// Compute an outer COSE_Encrypt0 as defined in Section 5.3
		// CIPHERTEXT_3 is the 'ciphertext' of the outer COSE_Encrypt0
		Encrypt0Message outer = new Encrypt0Message();
		outer.addAttribute(HeaderKeys.Algorithm, AlgorithmID.AES_CCM_16_64_128.AsCBOR(), Attribute.DO_NOT_SEND); // AEAD Algorithm
		
		outer.setExternal(TH_3); // external_aad = TH_3
		outer.SetContent( concat(ID_CRED_I, signature) ); // plaintext = ( ID_CRED_I / bstr_identifier, Signature_or_MAC_3, ? AD_3 )
		
		// IV_3ae
		// Nonce IV_3ae is the output of HKDF-Expand(PRK_3e2m, info, L). PRK_3e2m = PRK_2e for asymmetric
		byte[] IV_3ae_info = makeInfo("IV-GENERATION", AES_CCM_16_IV_LENGTH, outer.getProtectedAttributes().EncodeToBytes(), TH_3);
		byte[] IV_3ae = hkdf(AES_CCM_16_IV_LENGTH, PRK_3e2m, new byte[0], IV_3ae_info);
		outer.addAttribute(HeaderKeys.IV, CBORObject.FromObject(IV_3ae), Attribute.DO_NOT_SEND);

		// K_3ae
		byte[] K_3ae_info = makeInfo(new byte[]{algorithmID}, K_L, outer.getProtectedAttributes().EncodeToBytes(), TH_3);
		byte[] K_3ae = hkdf(K_L, PRK_3e2m, new byte[0], K_3ae_info);

		System.out.println( "Initiator K_3ae = " + printHexBinary(K_3ae) );

		outer.encrypt(K_3ae);
		byte[] CIPHERTEXT_3 = outer.EncodeToBytes();

		// Encode message3 as a sequence of CBOR encoded data items as specified in Section 4.4.1
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
		CBORGenerator generator = factory.createGenerator(stream);
		generator.writeBinary(CIPHERTEXT_3);
		generator.close();
		return stream.toByteArray();
	}

	private byte[] createData2(int c_r, byte[] pk) throws IOException {
		ByteArrayOutputStream stream = new ByteArrayOutputStream();
		CBORGenerator generator = factory.createGenerator(stream);
		generator.writeBinary(pk);
		generator.writeNumber(c_r);
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

}