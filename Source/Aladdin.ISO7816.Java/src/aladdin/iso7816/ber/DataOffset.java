package aladdin.iso7816.ber;
import aladdin.iso7816.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Информационный объект смещения (0x54)
///////////////////////////////////////////////////////////////////////////////
public class DataOffset extends DataObject
{
    // смещение данных
    public final int offset; 

    // конструктор закодирования
    public DataOffset(int offset) 
    {    
        // сохранить переданные параметры
        super(Authority.ISO7816, Tag.DATA_OFFSET); this.offset = offset; 
        
        // проверить корректность смещения
        if (offset < 0 || offset > Integer.MAX_VALUE) throw new IllegalArgumentException(); 
    } 
    // конструктор раскодирования
    public DataOffset(byte[] content) throws IOException
    {    
        // сохранить переданные параметры
        super(Authority.ISO7816, Tag.DATA_OFFSET, content); 
        
        // определить начало значимых байтов
        int i = 0; while (i < content.length && content[i] == 0) i++; 
        
        // проверить величину смещения
        if (content.length - i > 4) throw new IOException(); int value = 0; 
        
        // вычислить значение
        while (i < content.length) value = (value << 8) | (content[i] & 0xFF); 
        
        // проверить размер
        if (value < 0) throw new IOException(); this.offset = value; 
    } 
    // закодировать смещение
    @Override public byte[] content()
    {
        // закодировать нулевое смещение
        if (offset == 0) return new byte[0]; 
        
        // при достаточности одного байта
        else if (offset <= 0x0000FF) { byte[] encoded = new byte[1]; 
        
            // закодировать размер
            encoded[0] = (byte)(offset & 0xFF); return encoded; 
        }
        // при достаточности двух байтов
        else if (offset <= 0x00FFFF) { byte[] encoded = new byte[2]; 
        
            // закодировать размер
            encoded[0] = (byte)((offset >>> 8) & 0xFF); 
            encoded[1] = (byte)((offset      ) & 0xFF); return encoded; 
        }
        // при достаточности трех байтов
        else if (offset <= 0xFFFFFF) { byte[] encoded = new byte[3]; 
        
            // закодировать размер
            encoded[0] = (byte)((offset >>> 16) & 0xFF); 
            encoded[1] = (byte)((offset >>>  8) & 0xFF); 
            encoded[2] = (byte)((offset       ) & 0xFF); return encoded; 
        }
        // при достаточности четырех байтов
        else { byte[] encoded = new byte[4]; 
        
            // закодировать размер
            encoded[0] = (byte)((offset >>> 24) & 0xFF); 
            encoded[1] = (byte)((offset >>> 16) & 0xFF); 
            encoded[2] = (byte)((offset >>>  8) & 0xFF); 
            encoded[3] = (byte)((offset       ) & 0xFF); return encoded; 
        }
    }
}
