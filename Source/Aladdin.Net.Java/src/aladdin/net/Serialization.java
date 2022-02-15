package aladdin.net;
import java.io.*;

///////////////////////////////////////////////////////////////////////////
// Создание сериализаций данных
///////////////////////////////////////////////////////////////////////////
public abstract class Serialization 
{
    // создать способ записи/чтения данных
    public abstract Serializer getSerializer(Class<?> type); 
    
    // закодировать сообщение
    public final Message encode(Object type, Object value)
    {
        // определить тип данных
        Class<?> classType = (value != null) ? value.getClass() : null; 
        
        // получить способ сериализации данных
        Serializer serializer = getSerializer(classType); 
        
        // закодировать сообщение
        return serializer.encode(type, value); 
    }
    // раскодировать сообщение
    public final Object decode(Message message, Class<?> type) throws IOException
    {
        // проверить наличие сообщения
        if (message == null) return null; 
        
        // получить способ сериализации данных
        Serializer serializer = getSerializer(type); 
        
        // раскодировать сообщение
        return serializer.decode(message); 
    }
}
