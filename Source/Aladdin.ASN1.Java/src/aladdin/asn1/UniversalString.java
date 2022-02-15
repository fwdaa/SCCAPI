package aladdin.asn1;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Строка символов UTF-32
///////////////////////////////////////////////////////////////////////////
public final class UniversalString extends OctetString
{
    // проверить допустимость типа
    public static boolean isValidTag(Tag tag) { return tag.equals(Tag.UNIVERSALSTRING); }
    
    // проверить корректность объекта
    public static void validate(UniversalString encodable, 
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
    public static void validate(UniversalString encodable, 
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
    public UniversalString(IEncodable encodable) throws IOException
    {
        super(encodable); string = new String(content(), "UTF-32BE"); 
    }
    // конструктор при закодировании
    public UniversalString(String value) 
    {
        super(Tag.UNIVERSALSTRING, Utils.encodeString(value, "UTF-32BE")); string = value; 
    }
    // строка символов
    public final String str() { return string; } private final String string;
}