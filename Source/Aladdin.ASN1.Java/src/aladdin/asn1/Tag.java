package aladdin.asn1;
import java.io.*;

///////////////////////////////////////////////////////////////////////////
// Тип объекта
///////////////////////////////////////////////////////////////////////////
public final class Tag implements Serializable
{
    private static final long serialVersionUID = -7569211790664468161L;
    
    // тип объекта заданного класса
    public static Tag universal  (int value) { return new Tag(TagClass.UNIVERSAL  , value); }
    public static Tag application(int value) { return new Tag(TagClass.APPLICATION, value); }
    public static Tag context    (int value) { return new Tag(TagClass.CONTEXT    , value); }
    public static Tag privat     (int value) { return new Tag(TagClass.PRIVATE    , value); }
    
    // известные типы объектов
    public static final Tag ANY               = universal( 0);
    public static final Tag BOOLEAN           = universal( 1);
    public static final Tag INTEGER           = universal( 2);
    public static final Tag BITSTRING         = universal( 3);
    public static final Tag OCTETSTRING       = universal( 4);
    public static final Tag NULL              = universal( 5);
    public static final Tag OBJECTIDENTIFIER  = universal( 6);
    public static final Tag OBJECTDESCRIPTOR  = universal( 7);
    public static final Tag EXTERNAL          = universal( 8);
    public static final Tag REAL              = universal( 9);
    public static final Tag ENUMERATED        = universal(10);
    public static final Tag EMBEDDEDPDV       = universal(11);
    public static final Tag UTF8STRING        = universal(12);
    public static final Tag RELATIVEOID       = universal(13);
    public static final Tag SEQUENCE          = universal(16);
    public static final Tag SET               = universal(17);
    public static final Tag NUMERICSTRING     = universal(18); 
    public static final Tag PRINTABLESTRING   = universal(19);
    public static final Tag TELETEXSTRING     = universal(20);
    public static final Tag VIDEOTEXSTRING    = universal(21);
    public static final Tag IA5STRING         = universal(22);
    public static final Tag UTCTIME           = universal(23);
    public static final Tag GENERALIZEDTIME   = universal(24);
    public static final Tag GRAPHICSTRING     = universal(25);
    public static final Tag VISIBLESTRING     = universal(26);
    public static final Tag GENERALSTRING     = universal(27);
    public static final Tag UNIVERSALSTRING   = universal(28);
    public static final Tag CHARACTERSTRING   = universal(29);
    public static final Tag BMPSTRING         = universal(30);

    // класс объекта и тип объекта
    public final TagClass tagClass; public final int value;  

    // конструктор
    public Tag(TagClass tagClass, int value)
    {
        // сохранить переданные параметры
    	this.tagClass = tagClass; this.value = value; 
    }
    // получить хэш-код типа
    @Override public int hashCode()
    {
    	// получить хэш-код типа
    	return tagClass.hashCode() ^ value;
    }
    // сравнить два типа
    public boolean equals(Tag tag)
    {
    	// сравнить два типа
    	return tagClass == tag.tagClass && value == tag.value;
    }
    // сравнить два типа
    @Override public boolean equals(Object tag)
    {
		// сравнить два типа
		return (tag instanceof Tag) ? equals((Tag)tag) : false;
    }
    /////////////////////////////////////////////////////////////////////////////
    // Сравнить два типа
    /////////////////////////////////////////////////////////////////////////////
    public static class Comparator implements java.util.Comparator<Tag>
    {
        // выполнить сравнение тегов
        @Override public int compare(Tag A, Tag B) { return A.compareTo(B); }
    }
    // сравнить объекты
    public int compareTo(Tag other)
    {
        // сравнить значения
        if (tagClass.equals(other.tagClass)) return value - other.value; 
            
        // сравнить классы
        return tagClass.value() - other.tagClass.value(); 
    }
    /////////////////////////////////////////////////////////////////////////////
    // Кодирование типа
    /////////////////////////////////////////////////////////////////////////////
    public byte[] encode(PC pc) { byte[] encoded; 
         
		// учесть размер типа объекта
	    if (value >= 0x10000000) encoded = new byte[6]; else
		if (value >= 0x00200000) encoded = new byte[5]; else
		if (value >= 0x00004000) encoded = new byte[4]; else
		if (value >= 0x00000080) encoded = new byte[3]; else
		if (value >= 0x0000001F) encoded = new byte[2]; else 
                                 encoded = new byte[1];
            
		// закодировать класс объекта
        encoded[0] = (byte)(tagClass.value() << 6); 

		// закодировать способ кодирования
		if (pc.equals(PC.CONSTRUCTED)) encoded[0] |= 0x20;

		// закодировать первый байт типа объекта
        encoded[0] |= (value < 0x1F) ? (byte)value : (byte)0x1F;

		// для длинного типа объекта
		int cb = 1; if (value >= 0x10000000)
		{
            // закодировать часть типа
            encoded[cb++] = (byte)((((value & 0x70000000) >>> 28) & 0xFF) | 0x80);
        }
        // для длинного типа
        if (value >= 0x00200000)
		{
            // закодировать часть типа
            encoded[cb++] = (byte)((((value & 0x0FE00000) >>> 21) & 0xFF) | 0x80);
		}
		// для длинного типа
		if (value >= 0x00004000)
		{
            // закодировать часть типа
            encoded[cb++] = (byte)((((value & 0x001FC000) >>> 14) & 0xFF) | 0x80);
		}
		// для длинного типа
		if (value >= 0x00000080)
		{
            // закодировать часть типа
            encoded[cb++] = (byte)((((value & 0x00003F80) >>> 7) & 0xFF) | 0x80);
		}
		// для длинного типа
		if (value >= 0x0000001F)
		{
            // закодировать часть типа
        	encoded[cb++] = (byte)(value & 0x0000007F);
		}
        return encoded; 
    }
    /////////////////////////////////////////////////////////////////////////////
    // Раскодировать тип объекта со способом кодирования
    /////////////////////////////////////////////////////////////////////////////
    public static Tag decode(byte[] encoded, int ofs, int length) throws IOException
    {
        // создать поток ввода
        try (InputStream stream = new ByteArrayInputStream(encoded, ofs, length))
        {
            // раскодировать объект
            return decode(stream); 
        }
    }
    public static Tag decode(InputStream stream) throws IOException
    {
        // прочитать следующий байт
        int first = stream.read(); if (first < 0) throw new IOException(); 
        
        // раскодировать объект
        return decode(stream, (byte)first); 
    }
    public static Tag decode(InputStream stream, byte first) throws IOException
    {
        // определить класс объекта 
        TagClass tagClass = TagClass.UNIVERSAL; int value = 0; 

        // определить класс объекта 
		switch ((first >>> 6) & 0x03)
		{
		// определить класс объекта 
		case 0x01: tagClass = TagClass.APPLICATION;	break;
		case 0x02: tagClass = TagClass.CONTEXT;		break;
		case 0x03: tagClass = TagClass.PRIVATE;		break;
		}
		// извлечь тип объекта
		if ((first & 0x1F) < 0x1F) value = first & 0x1F; 
		else {
            // прочитать следующий байт
            int next = stream.read(); if (next < 0) throw new IOException(); 

			// для всех непоследних байтов типа
			while ((next & 0x80) == 0x80)
			{
				// скорректировать значение типа
				value <<= 7; value |= (next & 0x7F);

                // прочитать следующий байт
                next = stream.read(); if (next < 0) throw new IOException(); 
			}
			// учесть последний байт типа
			value <<= 7; value |= next & 0xFF;    
		}
        // вернуть раскодированный объект
        return new Tag(tagClass, value); 
    }
}
