package aladdin.iso7816;
import aladdin.asn1.*; 
import java.io.*;
import java.util.*;

///////////////////////////////////////////////////////////////////////////////
// Заголовок объекта
///////////////////////////////////////////////////////////////////////////////
public class Header 
{
    // тип объекта со способом кодирования и его размер
    public final Tag tag; public final int length; private byte[] encoded; 
    
    // раскодировать заголовок
    public static Header decode(byte[] encoded, int ofs, int size) throws IOException
    { 
        // раскодировать тип объекта со способом кодирования
        Tag asnTag = Tag.decode(encoded, ofs, size); 
        
        // указать начальные данные
        int cb = asnTag.encoded.length; int length = 0; 
            
        // проверить размер буфера
        if (size <= cb) throw new IOException(); 
            
        // извлечь размер содержимого
        if ((encoded[ofs + cb] & 0x80) == 0) length = encoded[ofs + cb++];
        else {
            // определить размер размера содержимого
            int cbLength = (encoded[ofs + cb++] & 0x7F);

            // проверить корректность размера
            if (cbLength == 0x7F) throw new IOException();
                
            // проверить размер буфера
            if (size <= cb + cbLength) throw new IOException(); 
                
            // для всех байтов размера содержимого
            for (int i = 0; i < cbLength; i++)
            {
                // скорректировать размер содержимого
                length <<= 8; length |= encoded[ofs + cb++] & 0xFF;
            }
        }
        // скопировать закодированное представление
        byte[] buffer = new byte[cb]; System.arraycopy(encoded, ofs, buffer, 0, cb);

        // создать закодированный объект
        return new Header(asnTag, length, buffer);
    }
    // конструктор
    private Header(Tag tag, int length, byte[] encoded)
    {
        // сохранить переданные параметры
        this.tag = tag; this.length = length; this.encoded = encoded;
    }
    // конструктор
    public Header(Tag tag, int length)
    {
        // сохранить переданные параметры
        this.tag = tag; this.length = length; this.encoded = null; 
    }
    public final byte[] encoded()
    {
        // проверить наличие представления
        if (encoded != null) return encoded; 
        
        // определить размер закодированного типа
        int cb = tag.encoded.length; int cbLength = 1; 
            
		// учесть размер размера содержимого
        if (length >= 0x01000000) cbLength += 4; else 
        if (length >= 0x00010000) cbLength += 3; else 
		if (length >= 0x00000100) cbLength += 2; else 
		if (length >= 0x00000080) cbLength += 1;

		// выделить память для закодирования
        encoded = new byte[cb + cbLength];

        // скопировать тип объекта
        System.arraycopy(tag.encoded, 0, encoded, 0, cb); 

		// для длинного размера
		if (length >= 0x01000000) { encoded[cb++] = (byte)0x84;

            // закодировать размер содержимого
            encoded[cb++] = (byte)(((length & 0x7F000000) >>> 24) & 0xFF);
            encoded[cb++] = (byte)(((length & 0x00FF0000) >>> 16) & 0xFF);
            encoded[cb++] = (byte)(((length & 0x0000FF00) >>> 8 ) & 0xFF);
            encoded[cb++] = (byte)(((length & 0x000000FF)       ) & 0xFF);
        }
		// для длинного размера
		else if (length >= 0x00010000) { encoded[cb++] = (byte)0x83;

            // закодировать размер содержимого
            encoded[cb++] = (byte)(((length & 0x00FF0000) >>> 16) & 0xFF);
            encoded[cb++] = (byte)(((length & 0x0000FF00) >>>  8) & 0xFF);
            encoded[cb++] = (byte)(((length & 0x000000FF)       ) & 0xFF);
		}
		// для длинного размера
		else if (length >= 0x00000100) { encoded[cb++] = (byte)0x82;

            // закодировать размер содержимого
            encoded[cb++] = (byte)(((length & 0x0000FF00) >>> 8) & 0xFF);
            encoded[cb++] = (byte)(((length & 0x000000FF)      ) & 0xFF);
        }
		// для длинного размера
		else if (length >= 0x00000080) { encoded[cb++] = (byte)0x81;

            // закодировать размер содержимого
            encoded[cb++] = (byte)(length & 0x000000FF);
		}
		// закодировать размер содержимого
        else encoded[cb++] = (byte)length; return encoded;
    }
    // извлечь требуемые поля из объекта
    public final IEncodable apply(IEncodable encodable) throws IOException
    {
        // получить тип представления
        Tag encodableTag = new Tag(encodable.tag(), encodable.pc()); 
            
        // проверить совпадение типа
        if (!tag.equals(encodableTag)) return null; 

        // проверить указание размера
        if (length == 0x00) return encodable; 
            
        // проверить необходимость усечения
        if (encodable.content().length <= length) return encodable;
        
        // проверить возможность усечения
        if (tag.pc.equals(PC.CONSTRUCTED)) throw new IOException();
        
        // изменить размер содержимого
        byte[] content = Arrays.copyOf(encodable.content(), length); 
            
        // закодировать объект
        return Encodable.encode(encodable.tag(), encodable.pc(), content); 
    }
}
