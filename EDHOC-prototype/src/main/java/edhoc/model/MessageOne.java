package edhoc.model;

import java.io.IOException;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;

public class MessageOne implements Message {

    private int methodCorr;
    private int suite;
    private byte[] publicKey;
    private int connectionIdentifier;

    public MessageOne(int METHOD_CORR, int SUITES_I, byte[] G_X, int C_I) {
        methodCorr = METHOD_CORR;
        suite = SUITES_I;
        publicKey = G_X;
        connectionIdentifier = C_I;
    }

    public int getMethod() {
        return methodCorr & 0x100;
    }

    public int getCorrelation() {
        return methodCorr % 4;
    }

}