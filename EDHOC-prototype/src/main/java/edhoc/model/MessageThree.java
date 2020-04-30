package edhoc.model;

public class MessageThree implements Message {

    private int method;

    public MessageThree(int m){
        method = m;
    }

    public int getMethod(){
        return method;
    }

}