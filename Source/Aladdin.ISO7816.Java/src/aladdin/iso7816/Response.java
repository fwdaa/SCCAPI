package aladdin.iso7816;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Ответ APDU
///////////////////////////////////////////////////////////////////////////
public class Response
{
    // код завершения
    public final byte[] data; public final short SW;

    // конструктор
    public Response(short sw) { this(new byte[0], sw); }
            
    // конструктор
    public Response(byte[] data, short sw)
    {
        // проверить корректность данных
        if ((sw & 0xFFFF) < 0x6100 || 0xA000 <= (sw & 0xFFFF)) 
        {
            // при ошибке выбросить исключение
            throw new IllegalArgumentException(); 
        }
        // сохранить переданные параметры
        this.data = data; SW = sw; encoded = new byte[data.length + 2];

        // скопировать данные
        System.arraycopy(data, 0, encoded, 0, data.length); 

        // закодировать код завершения
        encoded[encoded.length - 2] = (byte)(sw >>>  8); 
        encoded[encoded.length - 1] = (byte)(sw & 0xFF); 
    }
    // раскодировать ответ
    public Response(byte[] encoded) throws IOException
    {
        // проверить корректность размера
        if (encoded.length < 2) throw new IOException(); 

        // выделить память для данных
        data = new byte[encoded.length - 2]; this.encoded = encoded; 

        // скопировать данные
        System.arraycopy(encoded, 0, data, 0, data.length); 

        // раскодировать код завершения
        SW = (short)((encoded[encoded.length - 2] << 8) | encoded[encoded.length - 1]); 

        // проверить корректность данных
        if ((SW & 0xFFFF) < 0x6100 || 0xA000 <= (SW & 0xFFFF)) 
        {
            // при ошибке выбросить исключение
            throw new IOException(); 
        }
    }
    // признак отсутствия ошибок
    public static boolean normal(Response response) 
    { 
        // признак отсутствия ошибок
        return ((response.SW & 0xF000) == 0x9000 || (response.SW & 0xFF00) == 0x6100); 
    }
    // признак предупреждения
    public static boolean warning(Response response) 
    { 
        // признак предупреждения
        return (0x6200 <= (response.SW & 0xFFFF) && (response.SW & 0xFFFF) < 0x6400); 
    }
    // признак ошибки
    public static boolean error(Response response) 
    { 
        // проверить корректность данных
        if ((response.SW & 0xFFFF) < 0x6100 || 0xA000 <= (response.SW & 0xFFFF)) return true; 

        // признак ошибки
        return (response.SW & 0xFFFF) >= 0x6400; 
    }
    // закодированное представление
    public byte[] encoded() { return encoded; } private final byte[] encoded; 
}
