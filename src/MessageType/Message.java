package MessageType;

import java.io.Serializable;

public class Message implements Serializable {
    private String message;
    private String sender;
    private String receiver;

    public Message(String message, String from, String to) {
        this.message = message;
        this.sender = from;
        this.receiver = to;
    }

    public String getMessage() {
        return message;
    }

    public String getFrom() {
        return sender;
    }

    public String getTo() {
        return receiver;
    }
    
}

