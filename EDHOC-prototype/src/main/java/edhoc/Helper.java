package edhoc;

import java.io.IOException;

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