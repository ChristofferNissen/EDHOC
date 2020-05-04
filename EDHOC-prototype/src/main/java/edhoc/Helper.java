package edhoc;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.util.Base64;

import com.fasterxml.jackson.core.Version;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.fasterxml.jackson.dataformat.cbor.CBORParser;

import edhoc.model.Message;
import edhoc.model.MessageOne;
import edhoc.model.MessageThree;
import edhoc.model.MessageTwo;
import edhoc.model.deserializers.MessageOneDeserializer;
import edhoc.model.deserializers.MessageThreeDeserializer;
import edhoc.model.deserializers.MessageTwoDeserializer;

public class Helper {

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

	public static byte[] mergeArrays(byte[] a1, byte[] a2) {
		byte[] combined = new byte[a1.length + a2.length];
		int i = 0;
		for (byte b : a1) combined[i++] = b;
		for (byte b : a2) combined[i++] = b;
		return combined;
	}

	public static byte[] HMAC_SHA256(byte[] key, byte[] message) {
		byte opad = 0x5c;
		byte ipad = 0x36;
		int blockSize = 32;

		if (key.length > blockSize)
			key = sha256Hashing(key);
		else if (key.length < blockSize)
			key = pad(key, blockSize);

		byte[] iKeyPad = xor(key, ipad);
		byte[] oKeyPad = xor(key, opad);

		return sha256Hashing(mergeArrays(oKeyPad, sha256Hashing(mergeArrays(iKeyPad, message))));
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
			
			final byte[] hashedBytes = md.digest(cborEncodedBytes);
			final String hashedString = Base64.getEncoder().encodeToString(hashedBytes);
			final byte[] encodedHashedString = encodeAsCbor(hashedString);
			return encodedHashedString;
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