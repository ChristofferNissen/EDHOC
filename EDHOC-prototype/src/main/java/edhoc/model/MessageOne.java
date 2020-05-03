package edhoc.model;

public class MessageOne implements Message {

    private int method;

    public MessageOne(int m){
        method = m;
    }

    public int getMethod(){
        return method;
    }

}