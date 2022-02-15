package aladdin.asn1;
import java.io.*; 
import java.util.*;

///////////////////////////////////////////////////////////////////////////
// Закодированное представление объекта
///////////////////////////////////////////////////////////////////////////
public class Encodable implements IEncodable
{
    // тип объекта, содержимое объекта и закодированное представление
    private final Tag tag; private final PC pc; private byte[] content; private byte[] encoded;
    
    // конструктор
    protected Encodable(IEncodable encodable)
    {
        this.tag     = encodable.tag    ();   // тип объекта
        this.pc      = encodable.pc     ();   // способ кодирования
        this.content = encodable.content();   // содержимое объекта
        this.encoded = encodable.encoded();   // закодированное представление
    }
    // конструктор закодирования
    protected Encodable(Tag tag, PC pc)
    {
        this.tag     = tag;                   // тип объекта
        this.pc      = pc;                    // способ кодирования
        this.content = null;                  // содержимое объекта
        this.encoded = null;                  // закодированное представление
    }
    // конструктор раскодирования
    private Encodable(Tag tag, PC pc, byte[] content, byte[] encoded)
    {
        this.tag     = tag;                   // тип объекта
        this.pc      = pc;                    // способ кодирования
        this.content = content;               // содержимое объекта
        this.encoded = encoded;               // закодированное представление
    }
    // тип и способ кодирования
    @Override public final Tag tag() { return tag; }
    @Override public final PC  pc () { return pc;  }

    @Override public final byte[] content()
    {
        // проверить наличие представления
        if (content != null) return content; 
        
        // закодировать представление
		content = evaluateContent(); return content; 
    }
    protected byte[] evaluateContent() { return content; }

    @Override public final byte[] encoded()
    {
        // проверить наличие представления
		if (encoded != null) return encoded;

		// создать представление объекта
		return encoded = encode(tag, pc, content()).encoded();
    }
    /////////////////////////////////////////////////////////////////////////////
    // Сравнить два объекта
    /////////////////////////////////////////////////////////////////////////////
    @Override public int hashCode() { return encoded()[0]; }
    
    @Override public boolean equals(Object obj)
    {
        // сравнить два объекта
        return (obj instanceof IEncodable) ? equals((IEncodable)obj) : false;
    }
    public final boolean equals(IEncodable obj)
    {
		// выполнить тривиальные проверки
		if (obj == null) return false; if (this == obj) return true;
			
		// сравнить два объекта
		return Arrays.equals(encoded(), obj.encoded());
    }
    /////////////////////////////////////////////////////////////////////////////
    // Проверить отсутствие данных
    /////////////////////////////////////////////////////////////////////////////
    public static boolean isNullOrEmpty(IEncodable encodable)
    {
        // проверить отсутствие данных
        return encodable == null || encodable.content().length == 0; 
    }
    /////////////////////////////////////////////////////////////////////////////
    // Закодировать данные
    /////////////////////////////////////////////////////////////////////////////
    public static IEncodable encode(Tag tag, PC pc, byte[] content)
    {
        // закодировать тип со способом кодирования
        byte[] encodedTagPC = tag.encode(pc); 
        
        // определить размер закодированного типа
        int cb = encodedTagPC.length; int cbLength = 1; 
            
		// учесть размер размера содержимого
        if (content.length >= 0x01000000) cbLength += 4; else 
        if (content.length >= 0x00010000) cbLength += 3; else 
		if (content.length >= 0x00000100) cbLength += 2; else 
		if (content.length >= 0x00000080) cbLength += 1;

		// выделить память для закодирования
        byte[] encoded = new byte[cb + cbLength + content.length];
        
        // скопировать закодированный тип
        System.arraycopy(encodedTagPC, 0, encoded, 0, cb);

		// для длинного размера
		if (content.length >= 0x01000000) { encoded[cb++] = (byte)0x84;

            // закодировать размер содержимого
            encoded[cb++] = (byte)(((content.length & 0x7F000000) >>> 24) & 0xFF);
            encoded[cb++] = (byte)(((content.length & 0x00FF0000) >>> 16) & 0xFF);
            encoded[cb++] = (byte)(((content.length & 0x0000FF00) >>> 8 ) & 0xFF);
            encoded[cb++] = (byte)(((content.length & 0x000000FF)       ) & 0xFF);
        }
		// для длинного размера
		else if (content.length >= 0x00010000) { encoded[cb++] = (byte)0x83;

            // закодировать размер содержимого
            encoded[cb++] = (byte)(((content.length & 0x00FF0000) >>> 16) & 0xFF);
            encoded[cb++] = (byte)(((content.length & 0x0000FF00) >>>  8) & 0xFF);
            encoded[cb++] = (byte)(((content.length & 0x000000FF)       ) & 0xFF);
		}
		// для длинного размера
		else if (content.length >= 0x00000100) { encoded[cb++] = (byte)0x82;

            // закодировать размер содержимого
            encoded[cb++] = (byte)(((content.length & 0x0000FF00) >>> 8) & 0xFF);
            encoded[cb++] = (byte)(((content.length & 0x000000FF)      ) & 0xFF);
        }
		// для длинного размера
		else if (content.length >= 0x00000080) { encoded[cb++] = (byte)0x81;

            // закодировать размер содержимого
            encoded[cb++] = (byte)(content.length & 0x000000FF);
		}
		// закодировать размер содержимого
        else encoded[cb++] = (byte)content.length; 
        
        // скопировать содержимое
        System.arraycopy(content, 0, encoded, cb, content.length); 
        
        // вернуть закодированный объект
		return new Encodable(tag, pc, content, encoded);  
    }
    // раскодировать объект
    public static IEncodable decode(byte[] encoded) throws IOException
    {
		// раскодировать объект
		return decode(encoded, 0, encoded.length);
    }
    // раскодировать объект
    public static IEncodable decode(byte[] encoded, int ofs, int size) throws IOException
    { 
        // создать поток ввода
        try (InputStream stream = new ByteArrayInputStream(encoded, ofs, size))
        {
            // раскодировать объект
            return decode(stream); 
        }
    }
    // раскодировать объект
    public static IEncodable decode(InputStream stream) throws IOException
    {
        // прочитать следующий байт
        int first = stream.read(); if (first < 0) throw new IOException(); 

        // раскодировать объект
        return decode(stream, (byte)first); 
    }
    // раскодировать объект
    public static IEncodable decode(InputStream stream, byte first) throws IOException
    {
		// определить способ кодирования объекта
		PC pc = ((first & 0x20) != 0) ? PC.CONSTRUCTED : PC.PRIMITIVE; 
        
        // создать буфер для закодированного представления
        ByteArrayOutputStream encodedStream = new ByteArrayOutputStream(); 
        
        // прочитать тип объекта
        Tag tag = Tag.decode(stream, first); encodedStream.write(tag.encode(pc));
        
        // указать начальные данные
        int length = 0; byte[] content = null; 
        
        // прочитать следующий байт
        int next = stream.read(); if (next < 0) throw new IOException(); 
        
        // при указании размера содержимого
        encodedStream.write(next); if ((next & 0x80) == 0)
        {
            // извлечь размер содержимого
            length = next; content = new byte[length]; if (length != 0)
            {
                // извлечь содержимое объекта
                if (stream.read(content) < content.length) throw new IOException();
            
                // сохранить содержимое объекта
                encodedStream.write(content); 
            }
        }
        else {
            // определить размер размера содержимого
            int cbLength = next & 0x7F;
            
            // проверить корректность размера
            if (cbLength == 0x7F) throw new IOException();
            if (cbLength == 0x00) 
            {
                // проверить корректность данных
                if (pc.equals(PC.PRIMITIVE)) throw new IOException();
                
                // создать внутренний буфер
                ByteArrayOutputStream contentStream = new ByteArrayOutputStream(); 

                // раскодировать внутренний объект
                IEncodable obj = decode(stream); byte[] encoded = obj.encoded(); 

                // для всех внутренних объектов
                while (encoded.length != 2)
                {
                    // сохранить внутренннее представление
                    contentStream.write(encoded);
                    
                    // раскодировать внутренний объект
                    obj = decode(stream); encoded = obj.encoded(); 
                }
                // проверить корректность данных
                if (encoded[0] != 0 || encoded[1] != 0) throw new IOException();
                
                // сохранить внутренее представление
                content = contentStream.toByteArray(); 
                
                // сохранить содержимое объекта
                encodedStream.write(content); encodedStream.write(encoded);
            }
            else {
                // для всех байтов размера содержимого
                for (int i = 0; i < cbLength; i++)
                {
                    // прочитать следующий байт
                    next = stream.read(); if (next < 0) throw new IOException(); 
                    
                    // скорректировать размер содержимого
                    length <<= 8; length |= next & 0xFF; encodedStream.write(next); 
                }
                // выделить память для содержимого
                content = new byte[length]; if (length != 0)
                {
                    // извлечь содержимое объекта
                    if (stream.read(content) < content.length) throw new IOException();  

                    // сохранить содержимое объекта
                    encodedStream.write(content); 
                }
            }
        }
        // создать закодированный объект
        return new Encodable(tag, pc, content, encodedStream.toByteArray());
    }
}
