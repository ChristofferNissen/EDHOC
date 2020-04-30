package edhoc;

import java.io.IOException;
import java.util.Base64;
import java.security.MessageDigest;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;

import edhoc.model.Message;

public class Helper {

    public static byte[] EncodeAsCbor(Message m) throws IOException {
		final CBORFactory f = new CBORFactory();
		final ObjectMapper mapper = new ObjectMapper(f);
		// and then read/write data as usual
		byte[] cborData;
		cborData = mapper.writeValueAsBytes(m);
		return cborData;
    }
    
    public static Message DecodeFromCbor(byte[] cborData) throws IOException {
		final CBORFactory f = new CBORFactory();
		final ObjectMapper mapper = new ObjectMapper(f);
		// and then read/write data as usual
		final Message otherValue = mapper.readValue(cborData, Message.class); 
		return otherValue;
	}
	
	public static byte[] sha256Hashing(byte[] cborEncodedBytes) {
		try {
			final MessageDigest md = MessageDigest.getInstance("SHA-256");
			final CBORFactory f = new CBORFactory();
			final ObjectMapper mapper = new ObjectMapper(f);
			
			final byte[] hashedBytes = md.digest(cborEncodedBytes);
			final String hashedString = Base64.getEncoder().encodeToString(hashedBytes);
			final byte[] encodedHashedString = mapper.writeValueAsBytes(hashedString);
			return encodedHashedString;
		} catch (Exception e) {
			System.out.println("Hashing algorith not valid");
			return null;
		}
	}

}