package aladdin.net;
import aladdin.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Диалог взаимодействия
///////////////////////////////////////////////////////////////////////////
public abstract class Conversation extends Disposable
{
    // признак закрытия диалога
    public abstract boolean inactive(); 
    
    // создать способ записи/чтения данных
    public abstract Serializer getSerializer(Class<?> type); 
    
    // признак завершения диалога
    public boolean isEndDialog(Message message) { return false; } 
    
    // передать сообщение
    public final void send(Object type, Object value, int timeout) throws IOException 
    {
        // определить тип данных
        Class<?> classType = (value != null) ? value.getClass() : null; 
        
        // получить способ сериализации данных
        Serializer serializer = getSerializer(classType); 
        
        // закодировать и передать сообщение
        send(serializer.encode(type, value), timeout); 
    }
    // передать сообщение
    public abstract void send(Message message, int timeout) throws IOException; 
    // получить сообщение
    public abstract Message receive(int timeout) throws IOException; 
    
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
    // раскодировать исключение
    public abstract Throwable decodeException(Message message) throws IOException; 
}
