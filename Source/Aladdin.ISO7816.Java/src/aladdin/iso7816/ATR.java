package aladdin.iso7816;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// ATR смарт-карты
///////////////////////////////////////////////////////////////////////////
public class ATR
{
    // закодированное представление и исторические байты
    public final byte[] encoded; public final HistoricalBytes historicalBytes;
    
    // конструктор
    public ATR(byte[] encoded) throws IOException
    {
        // проверить корректность данных
        if (2 > encoded.length || encoded.length > 33) 
        {
            // при ошибке выбросить исключение
            throw new IOException();  
        }
        // проверить корректность данных
        if ((encoded[0] & 0x3B) != 0x3B) throw new IOException();

        // сохранить переданные параметры 
        int offset = 1; int cb = encoded[offset] & 0x0F; this.encoded = encoded;  

        // для всех последовательностей TA, TB, TC, TD
        for (int Y = encoded[offset++] & 0xF0; ; Y = encoded[offset++] & 0xF0)
        {
            // проверить наличие байтов TA, TB, TC и TD
            if ((Y & 0x10) != 0) offset++; if ((Y & 0x20) != 0) offset++;
            if ((Y & 0x40) != 0) offset++; if ((Y & 0x80) != 0) 
            {
                // проверить корректность размера
                if (encoded.length <= offset) throw new IOException();
            }
            else {
                // проверить корректность размера
                if (encoded.length < offset + cb) throw new IOException(); break; 
            }
        }
        // сохранить извлеченные объекты
        historicalBytes = new HistoricalBytes(encoded, offset, cb);  
    }
}
