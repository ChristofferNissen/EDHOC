package edhoc.model;

public class MessageTwo implements Message {

    private int method;

    public MessageTwo(int m){
        method = m;
    }

    public int getMethod(){
        return method;
    }
}