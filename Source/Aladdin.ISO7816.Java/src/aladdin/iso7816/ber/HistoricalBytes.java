package aladdin.iso7816.ber;
import aladdin.iso7816.*;
import java.io.*;

///////////////////////////////////////////////////////////////////////////
// Байты предыстории (0x5F 0x52)
///////////////////////////////////////////////////////////////////////////
public class HistoricalBytes extends DataObject
{
    // байты предыстории
    public final aladdin.iso7816.HistoricalBytes value; 

    // конструктор закодирования
    public HistoricalBytes(aladdin.iso7816.HistoricalBytes value) 
    {     
        // сохранить переданные параметры
        super(Authority.ISO7816, Tag.HISTORICAL_BYTES, value.encoded()); 
            
        // сохранить переданные параметры
        this.value = value;
    }
    // конструктор раскодирования
    public HistoricalBytes(byte[] content) throws IOException
    {
        // сохранить переданные параметры
        super(Authority.ISO7816, Tag.HISTORICAL_BYTES, content); 
            
        // раскодировать байты предыстории
        value = new aladdin.iso7816.HistoricalBytes(content, 0, content.length);
    }
}
