package aladdin.io;
import java.io.*;

///////////////////////////////////////////////////////////////////////////////
// Поток ввода из памяти
///////////////////////////////////////////////////////////////////////////////
public class MemoryInputStream extends InputStream
{
    // конструктор
    public MemoryInputStream(MemoryStream stream)
    
        // сохранить переданные параметры
        { this.stream = stream; } private final MemoryStream stream; 

    // размер доступных данных
    @Override public int available() { return stream.length() - stream.position(); }
    
    // прочитать байт
    @Override public int read() throws IOException
    {
        // прочитать значение байта
        byte[] buffer = new byte[1]; int cb = read(buffer, 0, 1); 
        
        // вернуть значение байта
        return (cb > 0) ? (buffer[0] & 0xFF) : -1; 
    }
    // прочитать данные
    @Override public int read(byte[] buffer, int offset, int length) throws IOException 
    {
        // прочитать данные
        return stream.read(buffer, offset, length); 
    }
    // закрыть поток
    @Override public void close() throws IOException { stream.flush(); }
}
