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

    public static byte[] EncodeAsCbor(Message m) throws IOException {
		final CBORFactory f = new CBORFactory();
		final ObjectMapper mapper = new ObjectMapper(f);
		// and then read/write data as usual
		byte[] cborData;
		cborData = mapper.writeValueAsBytes(m);
		return cborData;
    }
    
    public static MessageOne DecodeM1FromCbor(byte[] cborData) throws IOException {
		final CBORFactory f = new CBORFactory();
		final ObjectMapper mapper = new ObjectMapper(f);
		// and then read/write data as usual
		final MessageOne value = mapper.readValue(cborData, MessageOne.class); 
		return value;
    }
    
    public static MessageTwo DecodeM2FromCbor(byte[] cborData) throws IOException {
		final CBORFactory f = new CBORFactory();
		final ObjectMapper mapper = new ObjectMapper(f);
		// and then read/write data as usual
		final MessageTwo value = mapper.readValue(cborData, MessageTwo.class); 
		return value;
    }
    
    public static MessageThree DecodeM3FromCbor(byte[] cborData) throws IOException {
		final CBORFactory f = new CBORFactory();
		final ObjectMapper mapper = new ObjectMapper(f);
		// and then read/write data as usual
		final MessageThree value = mapper.readValue(cborData, MessageThree.class); 
		return value;
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