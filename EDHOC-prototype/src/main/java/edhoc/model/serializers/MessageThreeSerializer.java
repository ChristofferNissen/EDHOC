package edhoc.model.serializers;

import java.io.IOException;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;

import edhoc.model.MessageThree;

public class MessageThreeSerializer extends StdSerializer<MessageThree>{

    public MessageThreeSerializer() {
        this(null);
    }

    public MessageThreeSerializer(Class<MessageThree> t) {
        super(t);
    }

    @Override
    public void serialize(MessageThree m1, JsonGenerator jsonGenerator, SerializerProvider serializer)
            throws IOException {
        jsonGenerator.writeStartObject();
        // jsonGenerator.writeStringField("method", String.format("{0}", m1.getMethod()));
        jsonGenerator.writeEndObject();
    }

}