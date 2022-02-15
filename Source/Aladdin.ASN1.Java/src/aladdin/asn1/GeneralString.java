package aladdin.asn1;
import java.io.*;

///////////////////////////////////////////////////////////////////////////
// Строка символов
///////////////////////////////////////////////////////////////////////////
public final class GeneralString extends OctetString
{
    // проверить допустимость типа
    public static boolean isValidTag(Tag tag) { return tag.equals(Tag.GENERALSTRING); }
    
    // проверить корректность объекта
    public static void validate(GeneralString encodable, 
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
    public static void validate(GeneralString encodable, 
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
    public GeneralString(IEncodable encodable) throws IOException
    {
        super(encodable); string = new String(content()); 
    }
    // конструктор при закодировании
    public GeneralString(String value) 
    {
        super(Tag.GENERALSTRING, value.getBytes()); string = value; 
    }
    // строка символов
    public final String str() { return string; } private final String string;
}