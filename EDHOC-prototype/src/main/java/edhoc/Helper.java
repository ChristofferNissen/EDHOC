package edhoc;

import java.io.IOException;

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

}