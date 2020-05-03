package edhoc.model.deserializers;

import java.io.IOException;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.ObjectCodec;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;

import edhoc.model.MessageThree;

public class MessageThreeDeserializer extends StdDeserializer<MessageThree> {

    public MessageThreeDeserializer() {
        this(null);
    }

    public MessageThreeDeserializer(Class<?> vc) {
        super(vc);
    }

    @Override
    public MessageThree deserialize(JsonParser parser, DeserializationContext deserializer) throws IOException {
        
        ObjectCodec codec = parser.getCodec();
        JsonNode node = codec.readTree(parser);

        // try catch block
        JsonNode methodNode = node.get("method");
        int method = methodNode.asInt();
        MessageThree m = new MessageThree(method);

        return m;
    }
}