package aladdin.io;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Сериализация данных
///////////////////////////////////////////////////////////////////////////
public abstract class Serializer 
{
    // раскодировать объект
    public abstract Object decode(byte[] encoded) throws IOException; 
    
    // закодировать объект
    public abstract byte[] encode(Object obj); 
}
