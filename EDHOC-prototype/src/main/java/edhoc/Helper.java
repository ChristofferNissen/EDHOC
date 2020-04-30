package edhoc;

import java.io.IOException;

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

}