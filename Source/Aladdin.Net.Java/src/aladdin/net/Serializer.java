package aladdin.net;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Сериализация данных
///////////////////////////////////////////////////////////////////////////
public abstract class Serializer 
{
    // закодировать объект
    public abstract Message encode(Object type, Object value); 
    // раскодировать объект
    public abstract Object decode(Message message) throws IOException; 
}
