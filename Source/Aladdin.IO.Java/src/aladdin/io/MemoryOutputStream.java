package aladdin.io;
import java.io.*;

///////////////////////////////////////////////////////////////////////////////
// Поток вывода в память
///////////////////////////////////////////////////////////////////////////////
public class MemoryOutputStream extends OutputStream
{
    // конструктор
    public MemoryOutputStream(MemoryStream stream)
    
        // сохранить переданные параметры
        { this.stream = stream; } private final MemoryStream stream; 

    // записать байт
    @Override public void write(int b) throws IOException
    {
        // указать записываемый байт
        byte[] buffer = new byte[1]; buffer[0] = (byte)(b & 0xFF); 
        
        // записать данные
        write(buffer, 0, buffer.length); 
    }
    // записать данные
    @Override public void write(byte[] buffer, int offset, int length) throws IOException 
    {
        // записать данные
        stream.write(buffer, offset, length); 
    }
    // сохранить изменения 
    @Override public void flush() throws IOException { stream.flush(); }

    // закрыть поток
    @Override public void close() throws IOException { flush(); }
}
