package edhoc;

import java.io.IOException;
import java.security.MessageDigest;
import java.util.Base64;

import com.fasterxml.jackson.core.Version;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;

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

    public static Object decodeFromCbor(byte[] cborData, Class<?> cls) throws IOException {
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