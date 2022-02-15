package aladdin.net;
import java.io.*;

///////////////////////////////////////////////////////////////////////
// Сериализация бинарных данных
///////////////////////////////////////////////////////////////////////
public class BinarySerializer<T> extends Serializer
{
    // способ сериализации
    private final aladdin.io.Serializer serializer; 

    // конструктор
    public BinarySerializer() { this(new aladdin.io.BinarySerializer()); }
    
    // конструктор
    public BinarySerializer(aladdin.io.Serializer serializer)
    {
        // сохранить переданные параметры
        this.serializer = serializer; 
    }
    // закодировать объект
    @SuppressWarnings({"unchecked"}) 
    @Override public Message encode(Object type, Object value)
    {
        // проверить наличие объекта
        if (value == null) return new BinaryMessage<T>((T)type, new byte[0]); 
        
        // закодировать объект
        return new BinaryMessage<T>((T)type, serializer.encode(value)); 
    }
    // раскодировать объект
    @SuppressWarnings({"unchecked"}) 
    @Override public Object decode(Message message) throws IOException
    {
        // получить содержимое объекта
        byte[] body = ((BinaryMessage<T>)message).body(); 
        
        // раскодировать объект
        if (serializer != null) return serializer.decode(body); 
        
        // проверить допустимость отсутствия объекта
        if (body.length == 0) return null; throw new IOException();
    }
}
