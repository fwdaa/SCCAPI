package aladdin.asn1;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Строка символов ISO-646
///////////////////////////////////////////////////////////////////////////
public class VisibleString extends OctetString
{
    // проверить допустимость типа
    public static boolean isValidTag(Tag tag) { return tag.equals(Tag.VISIBLESTRING); }
    
    // проверить корректность объекта
    public static void validate(VisibleString encodable, 
        boolean encode, java.lang.Integer min, java.lang.Integer max) throws IOException
    {
		// проверить корректность
		if (encodable != null && encodable.str().length() < min) 
        {
            // ошибка - некорректный объект
            if (encode) throw new IllegalArgumentException(); else throw new IOException();
        }
		// проверить корректность
		if (encodable != null && encodable.str().length() > max) 
        {
            // ошибка - некорректный объект
            if (encode) throw new IllegalArgumentException(); else throw new IOException();
        }
    }
    // проверить корректность объекта
    public static void validate(VisibleString encodable, 
        boolean encode, java.lang.Integer min) throws IOException
    {
		// проверить корректность
		if (encodable != null && encodable.str().length() < min) 
        {
            // ошибка - некорректный объект
            if (encode) throw new IllegalArgumentException(); else throw new IOException();
        }
	}
    // конструктор при раскодировании
    public VisibleString(IEncodable encodable) throws IOException
    {
        super(encodable); string = new String(content(), "US-ASCII"); 
    }
    // конструктор при закодировании
    protected VisibleString(Tag tag, String value) 
    { 
        super(tag, Utils.encodeString(value, "US-ASCII")); string = value;
    }
    // конструктор при закодировании
    public VisibleString(String value)
    {
        this(Tag.VISIBLESTRING, value);  
    }
    // строка символов
    public final String str() { return string; } private final String string;
}   