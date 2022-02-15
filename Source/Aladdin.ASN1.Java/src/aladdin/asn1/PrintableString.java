package aladdin.asn1;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Строка печатаемых символов
///////////////////////////////////////////////////////////////////////////
public final class PrintableString extends OctetString
{
    // проверить допустимость типа
    public static boolean isValidTag(Tag tag) { return tag.equals(Tag.PRINTABLESTRING); }
    
    // проверить корректность объекта
    public static void validate(PrintableString encodable, 
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
    public static void validate(PrintableString encodable, 
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
    public PrintableString(IEncodable encodable) throws IOException
    {
        super(encodable); string = new String(content(), "US-ASCII"); 
    }
    // конструктор при закодировании
    public PrintableString(String value) 
    {
        super(Tag.PRINTABLESTRING, Utils.encodeString(value, "US-ASCII")); string = value; 
    }
    // строка символов
    public final String str() { return string; } private final String string;
}