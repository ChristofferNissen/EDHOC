package edhoc.model.serializers;

import java.io.IOException;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;

import edhoc.model.MessageTwo;

public class MessageTwoSerializer extends StdSerializer<MessageTwo>{

    public MessageTwoSerializer() {
        this(null);
    }

    public MessageTwoSerializer(Class<MessageTwo> t) {
        super(t);
    }

    @Override
    public void serialize(MessageTwo m1, JsonGenerator jsonGenerator, SerializerProvider serializer)
            throws IOException {
        jsonGenerator.writeStartObject();
        // jsonGenerator.writeStringField("method", String.format("{0}", m1.getMethod()));
        jsonGenerator.writeEndObject();
    }

}