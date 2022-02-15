package aladdin.capi.software;
import aladdin.capi.*;
import java.util.*;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Хранилище в памяти программных контейнеров
///////////////////////////////////////////////////////////////////////////
public class MemoryStore extends ContainerStore
{
	// конструктор
	public MemoryStore(CryptoProvider provider)
    {
        // сохранить переданные параметры
        super(provider, Scope.SYSTEM); 
    }
    // имя хранилища
    @Override public String name() { return "MEMORY"; }
    
	///////////////////////////////////////////////////////////////////////
	// Управление физическими потоками
	///////////////////////////////////////////////////////////////////////
    @Override
    protected ContainerStream createStream(Object name) throws IOException
    {
        // выполнить преобразование типа
        aladdin.capi.MemoryStream stream = (aladdin.capi.MemoryStream)name; 

        // проверить отсутствие данных
        if (stream.length() != 0) throw new IOException(); 

        // открыть хранилище
        return new MemoryStream(stream, true); 
    }
    @Override
    protected ContainerStream openStream(Object name, String access)
    {
        if (name instanceof aladdin.capi.MemoryStream)
        {
            // выполнить преобразование типа
            aladdin.capi.MemoryStream stream = (aladdin.capi.MemoryStream)name; 

            // открыть хранилище
            return new MemoryStream(stream, access.equals("rw")); 
        }
        else {
            // проверить корректность параметров
            if (!access.equals("r")) throw new IllegalArgumentException(); 

            // раскодировать содержимое
            byte[] content = Base64.getDecoder().decode((String)name); 
                    
            // указать используемый поток
            aladdin.capi.MemoryStream stream = new aladdin.capi.MemoryStream(content);

            // открыть хранилище
            return new MemoryStream(stream, false);
        }
    }
    @Override
    protected void deleteStream(Object name) throws IOException
    {
        // выполнить преобразование типа
        aladdin.capi.MemoryStream stream = (aladdin.capi.MemoryStream)name; 

        // удалить содержимое
        stream.position(0); stream.write(new byte[0], 0, 0);
    }
	///////////////////////////////////////////////////////////////////////////
    // Хранилище байтовых данных в байтовом потоке
	///////////////////////////////////////////////////////////////////////////
    private static final class MemoryStream extends ContainerStream
    {
	    // байтовый поток и допустимость записи
	    private final aladdin.capi.MemoryStream stream; public final boolean canWrite;
        
	    // конструктор
	    public MemoryStream(aladdin.capi.MemoryStream stream, boolean canWrite)
	    {
		    // сохранить переданные параметры
		    this.stream = stream; this.canWrite = canWrite; 
        }
        // имя контейнера
        @Override public Object name() { return stream; }
        
        // уникальный идентификатор
        @Override public String uniqueID() { return null; }

        // прочитать данные
        @Override public byte[] read() 
        {
            // выделить буфер требуемого размера
            byte[] buffer = new byte[stream.length()]; stream.position(0);
                
            // прочитать данные
            stream.read(buffer, 0, buffer.length); return buffer; 
        }
	    // записать данные
	    @Override public void write(byte[] buffer) throws IOException
	    {
		    // проверить допустимость записи
		    if (!canWrite) throw new IOException(); 

            // записать данные
            stream.position(0); stream.write(buffer, 0, buffer.length); 
	    }
    }
}
