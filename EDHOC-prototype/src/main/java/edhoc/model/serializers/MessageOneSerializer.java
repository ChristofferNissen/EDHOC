package edhoc.model.serializers;

import java.io.IOException;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;

import edhoc.model.MessageOne;

public class MessageOneSerializer extends StdSerializer<MessageOne>{

    public MessageOneSerializer() {
        this(null);
    }

    public MessageOneSerializer(Class<MessageOne> t) {
        super(t);
    }

    @Override
    public void serialize(MessageOne m1, JsonGenerator jsonGenerator, SerializerProvider serializer)
            throws IOException {
        jsonGenerator.writeStartObject();
        jsonGenerator.writeStringField("method", String.format("{0}", m1.getMethod()));
        jsonGenerator.writeEndObject();
    }

}