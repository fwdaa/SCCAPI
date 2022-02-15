package aladdin.net;

///////////////////////////////////////////////////////////////////////////
// Сообщение с бинарным содержимым
///////////////////////////////////////////////////////////////////////////
public class BinaryMessage<T> extends Message
{
    // тип сообщения и содержимое сообщения
    private final T type; private final byte[] body; 

    // конструктор
    public BinaryMessage(T type, byte[] body) 
    { 
        // сохранить переданные параметры
        this.type = type; this.body = body; 
    }
    // тип сообщения
    @Override public T type() { return type; } 

    // содержимое сообщения
    public byte[] body() { return body; } 
}
