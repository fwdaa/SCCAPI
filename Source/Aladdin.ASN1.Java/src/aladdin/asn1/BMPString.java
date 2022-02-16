package aladdin.asn1;
import java.io.*;

///////////////////////////////////////////////////////////////////////////
// Строка двухбайтовых символов Unicode
///////////////////////////////////////////////////////////////////////////
public final class BMPString extends OctetString
{
    // проверить допустимость типа
    public static boolean isValidTag(Tag tag) { return tag.equals(Tag.BMPSTRING); }
    
    // проверить корректность объекта
    public static void validate(BMPString encodable, 
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
    public static void validate(BMPString encodable, 
        boolean encode, java.lang.Integer min) throws IOException
    {
    	// проверить наличие объекта
		if (encodable == null) return;
		
		// проверить корректность
		if (encodable.str().length() < min) 
        {
            // ошибка - некорректный объект
            if (encode) throw new IllegalArgumentException(); else throw new IOException();
        }
	}
    // конструктор при раскодировании
    public BMPString(IEncodable encodable) throws IOException
    {
        super(encodable); string = new String(content(), "UTF-16BE"); 
    }
    // конструктор при закодировании
    public BMPString(String value) 
    {
        super(Tag.BMPSTRING, Utils.encodeString(value, "UTF-16BE")); string = value; 
    }
    // строка символов
    public final String str() { return string; } private final String string;
}