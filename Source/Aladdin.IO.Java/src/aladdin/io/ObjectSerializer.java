package aladdin.io;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Сериализация объектов в поток
///////////////////////////////////////////////////////////////////////////
public class ObjectSerializer extends Serializer
{
    // прочитать объект из потока
    public Object read(InputStream stream) throws IOException
    {
        // преобразовать тип потока
        ObjectInputStream inputStream = new ObjectInputStream(stream); 

        // прочитать из потока
        try { return (Serializable)inputStream.readObject(); }

        // при ошибке выбросить исключение
        catch (ClassNotFoundException e) { throw new IOException(e); }
    }
    // записать объект в поток
    public void write(Object obj, OutputStream stream) throws IOException
    {
        // преобразовать тип потока
        ObjectOutputStream outputStream = new ObjectOutputStream(stream); 

        // записать в поток
        outputStream.writeObject(obj); outputStream.flush();
    }
    // раскодировать объект
    @Override
    public Object decode(byte[] encoded) throws IOException
    {
        // проверить наличие данных
        if (encoded.length == 0) return null; 
            
        // создать поток
        try (ByteArrayInputStream stream = new ByteArrayInputStream(encoded))
        {
            // раскодировать объект
            return read(stream);
        }
    }
    // закодировать объект
    @Override
    public byte[] encode(Object obj) 
    {
        // проверить указание объекта
        if (obj == null) return new byte[0]; 
        try { 
            // создать поток
            try (ByteArrayOutputStream stream = new ByteArrayOutputStream())
            {
                // закодировать объект
                write(obj, stream); return stream.toByteArray(); 
            }
        }
        // обработать возможную ошибку
        catch (IOException e) { throw new IllegalArgumentException(e); }
    }
}
