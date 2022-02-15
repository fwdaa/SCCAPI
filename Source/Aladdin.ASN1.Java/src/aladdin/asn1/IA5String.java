package aladdin.asn1;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Строка символов ASCII
///////////////////////////////////////////////////////////////////////////
public final class IA5String extends OctetString
{
    // проверить допустимость типа
    public static boolean isValidTag(Tag tag) { return tag.equals(Tag.IA5STRING); }
    
    // проверить корректность объекта
    public static void validate(IA5String encodable, 
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
    public static void validate(IA5String encodable, 
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
    public IA5String(IEncodable encodable) throws IOException
    {
        super(encodable); string = new String(content(), "US-ASCII"); 
    }
    // конструктор при закодировании
    public IA5String(String value) 
    {
        super(Tag.IA5STRING, Utils.encodeString(value, "US-ASCII")); string = value; 
    }
    // строка символов
    public final String str() { return string; } private final String string;
}