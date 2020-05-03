package edhoc.model.deserializers;

import java.io.IOException;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.ObjectCodec;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;

import edhoc.model.MessageOne;

public class MessageOneDeserializer extends StdDeserializer<MessageOne> {

    public MessageOneDeserializer() {
        this(null);
    }

    public MessageOneDeserializer(Class<?> vc) {
        super(vc);
    }

    @Override
    public MessageOne deserialize(JsonParser parser, DeserializationContext deserializer) throws IOException {
        
        ObjectCodec codec = parser.getCodec();
        JsonNode node = codec.readTree(parser);

        // try catch block
        JsonNode methodNode = node.get("method");
        int method = methodNode.asInt();
        MessageOne m = new MessageOne(method);

        return m;
    }
}