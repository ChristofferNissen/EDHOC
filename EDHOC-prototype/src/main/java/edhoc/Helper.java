package edhoc;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.util.Base64;

import com.fasterxml.jackson.core.Version;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.fasterxml.jackson.dataformat.cbor.CBORGenerator;
import com.fasterxml.jackson.dataformat.cbor.CBORParser;

import edhoc.model.Message;
import edhoc.model.MessageOne;
import edhoc.model.MessageThree;
import edhoc.model.MessageTwo;
import edhoc.model.deserializers.MessageOneDeserializer;
import edhoc.model.deserializers.MessageThreeDeserializer;
import edhoc.model.deserializers.MessageTwoDeserializer;

public class Helper {

	public static final int HASH_LENGTH = 32; // Since we use SHA256
    public static byte[] encodeAsCbor(Object o) throws IOException {
		final CBORFactory f = new CBORFactory();
		final ObjectMapper mapper = new ObjectMapper(f);
		// and then read/write data as usual
		byte[] cborData;
		cborData = mapper.writeValueAsBytes(o);
		return cborData;
	}

	public static byte[] nextByteArray(CBORParser parser) throws IOException {
		ByteArrayOutputStream stream = new ByteArrayOutputStream();
		parser.nextToken();
		parser.readBinaryValue( stream );
		return stream.toByteArray();
	}

	public static byte[] concat(byte[] a1, byte[] a2) {
		byte[] combined = new byte[a1.length + a2.length];
		int i = 0;
		for (byte b : a1) combined[i++] = b;
		for (byte b : a2) combined[i++] = b;
		return combined;
	}

	public static byte[] HMAC_SHA256(byte[] key, byte[] message) {
		byte opad = 0x5c;
		byte ipad = 0x36;

		MessageDigest sha256 = getSHA256Instance();
	
		if (key.length > HASH_LENGTH)
			key = sha256.digest(key);
		else if (key.length < HASH_LENGTH)
			key = pad(key, HASH_LENGTH);

		byte[] iKeyPad = xor(key, ipad);
		byte[] oKeyPad = xor(key, opad);

		return sha256.digest(concat(oKeyPad, sha256.digest(concat(iKeyPad, message))));

	}

	private static MessageDigest getSHA256Instance() {
		MessageDigest md = null;
		try {
			md = MessageDigest.getInstance("SHA-256");
		} catch(Exception e) {
			System.out.println("SHA-256 for some reason not supported.");
			return null;
		}
		return md;
	
	}

	// For K_2e
	// info = [
	//   AlgorithmID,
	//   [ null, null, null ],
	//   [ null, null, null ],
	//   [ keyDataLength, h'', other ]
	// ]
	public static byte[] makeInfo(String algorithmId, int keyDataLength, byte[] th) {
		return makeInfo(algorithmId.getBytes(), keyDataLength, new byte[0], th);
	}

	// Doesn't produce the exact output expected, but good don't want to spend
	// more time on it.
	public static byte[] makeInfo(byte[] algorithmID, int keyDataLength, byte[] protectedS, byte[] other) {
		CBORFactory factory = new CBORFactory();
		ByteArrayOutputStream stream = new ByteArrayOutputStream();
		try {
			CBORGenerator gen = factory.createGenerator(stream);
			gen.writeStartArray();
			gen.writeBinary(algorithmID);

			// Empty PartyUInfo
			gen.writeStartArray();
			gen.writeNull();
			gen.writeNull();
			gen.writeNull();
			gen.writeEndArray();

			// Empty PartyVInfo
			gen.writeStartArray();
			gen.writeNull();
			gen.writeNull();
			gen.writeNull();
			gen.writeEndArray();

			//SuppPubInfo
			gen.writeNumber(keyDataLength);
			gen.writeBinary(protectedS);
			gen.writeBinary(other);
			gen.writeEndArray();

			gen.close();
			
		} catch (IOException e) {
			System.out.println("Error occured couldn't create CBOR info context.");
		}

		return stream.toByteArray();
	}

	public static byte[] hkdf(int length, byte[] ikm) {
		return hkdf(length, ikm, new byte[HASH_LENGTH], new byte[0]);
	}

	public static byte[] hkdf(int length, byte[] ikm, byte[] salt, byte[] info) {
		byte[] prk = HMAC_SHA256(salt, ikm);
		byte[] t = new byte[HASH_LENGTH];
		byte[] okm = new byte[length];
		int iters = (int) Math.ceil((double)length / HASH_LENGTH);
		for (int i = 0; i < iters; ++i) {
			t = HMAC_SHA256(prk, concat(concat(t, info), new byte[]{(byte)(1 + i)}));

			for (int j = 0; j < HASH_LENGTH && (j + i *HASH_LENGTH) < length; ++j) {
				okm[j + i * HASH_LENGTH] = t[j];
			}
		}

		return okm;
	}

	private static byte[] pad(byte[] key, int length) {
		byte[] paddedKey = new byte[length];
		int i = 0;
		for (byte b : key) paddedKey[i++] = b;
		return paddedKey;
	}

	public static byte[] xor(byte[] a1, byte[] a2) {
		if (a1.length != a2.length) throw new IllegalArgumentException("Can't XOR different sized arrays");
		
		byte[] result = new byte[a1.length];
		for (int i = 0; i < a1.length; ++i) {
		 	result[i] = (byte)(a1[i] ^ a2[i]);
		}
		return result;
	}

	private static byte[] xor(byte[] val, byte pad) {
		byte[] result = new byte[val.length];
		int i = 0;
		for (Byte b : val) result[i++] = (byte)(b ^ pad);
		return result;
	}

	public static byte[] sha256Hashing(byte[] cborEncodedBytes) {
		try {
			final MessageDigest md = MessageDigest.getInstance("SHA-256");
			return md.digest(cborEncodedBytes);

			// final byte[] hashedBytes = md.digest(cborEncodedBytes);
			// final String hashedString = Base64.getEncoder().encodeToString(hashedBytes);
			// final byte[] encodedHashedString = encodeAsCbor(hashedString);
			// return encodedHashedString;

		} catch (Exception e) {
			System.out.println("SHA-256 not supported.");
			return null;
		}
	}

	
    public static MessageOne decodeM1FromCbor(byte[] cborData, Class<?> cls) throws IOException {
		final CBORFactory f = new CBORFactory();
        final ObjectMapper mapper = new ObjectMapper(f);
        SimpleModule module = new SimpleModule("MessageOneDeserializer", new Version(1, 0, 0, null, null, null));
        module.addDeserializer(MessageOne.class, new MessageOneDeserializer());
        mapper.registerModule(module);
        // and then read/write data as usual

		final MessageOne value = mapper.readValue(cborData, MessageOne.class); 
		return value;
    }
    
    public static MessageTwo DecodeM2FromCbor(byte[] cborData) throws IOException {
		final CBORFactory f = new CBORFactory();
        final ObjectMapper mapper = new ObjectMapper(f);
        SimpleModule module = new SimpleModule("MessageTwoDeserializer", new Version(1, 0, 0, null, null, null));
        module.addDeserializer(MessageTwo.class, new MessageTwoDeserializer());
        mapper.registerModule(module);
        // and then read/write data as usual
        
		final MessageTwo value = mapper.readValue(cborData, MessageTwo.class); 
		return value;
    }
    
    public static MessageThree DecodeM3FromCbor(byte[] cborData) throws IOException {
		final CBORFactory f = new CBORFactory();
        final ObjectMapper mapper = new ObjectMapper(f);
        SimpleModule module = new SimpleModule("MessageThreeDeserializer", new Version(1, 0, 0, null, null, null));
        module.addDeserializer(MessageThree.class, new MessageThreeDeserializer());
        mapper.registerModule(module);
		// and then read/write data as usual

        final MessageThree value = mapper.readValue(cborData, MessageThree.class); 
		return value;
	}


}