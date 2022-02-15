package aladdin.capi.software;
import aladdin.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Поток бинарных данных
///////////////////////////////////////////////////////////////////////////
public abstract class ContainerStream extends RefObject
{
    // имя и уникальный идентификатор
    public abstract Object name(); public abstract String uniqueID(); 
    
    // прочитать данные
    public abstract byte[] read() throws IOException; 
    
    // записать данные
    public abstract void write(byte[] buffer) throws IOException; 
}
