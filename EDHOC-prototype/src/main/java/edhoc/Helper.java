package edhoc;

import java.io.IOException;
import java.util.Base64;
import java.security.MessageDigest;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;

import edhoc.model.Message;
import edhoc.model.MessageOne;
import edhoc.model.MessageThree;
import edhoc.model.MessageTwo;

public class Helper {

    public static byte[] encodeAsCbor(Object o) throws IOException {
		final CBORFactory f = new CBORFactory();
		final ObjectMapper mapper = new ObjectMapper(f);
		// and then read/write data as usual
		byte[] cborData;
		cborData = mapper.writeValueAsBytes(o);
		return cborData;
    }
    
    public static Object decodeFromCbor(byte[] cborData, Class<?> cls) throws IOException {
		final CBORFactory f = new CBORFactory();
		final ObjectMapper mapper = new ObjectMapper(f);
		// and then read/write data as usual
		final Object value = mapper.readValue(cborData, cls); 
		return value;
    }
	
	public static byte[] sha256Hashing(byte[] cborEncodedBytes) {
		try {
			final MessageDigest md = MessageDigest.getInstance("SHA-256");
			
			final byte[] hashedBytes = md.digest(cborEncodedBytes);
			final String hashedString = Base64.getEncoder().encodeToString(hashedBytes);
			final byte[] encodedHashedString = encodeAsCbor(hashedString);
			return encodedHashedString;
		} catch (Exception e) {
			System.out.println("Hashing algorith not valid");
			return null;
		}
	}

}