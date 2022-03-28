package aladdin.asn1;
import java.lang.Integer; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Строка символов Videotex
///////////////////////////////////////////////////////////////////////////
public final class VideotexString extends OctetString
{
    private static final long serialVersionUID = 96864326161807096L;
    
    // проверить допустимость типа
    public static boolean isValidTag(Tag tag) { return tag.equals(Tag.VIDEOTEXSTRING); }
    
    // проверить корректность объекта
    public static void validate(VideotexString encodable, boolean encode, Integer min, Integer max) throws IOException
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
    public static void validate(VideotexString encodable, boolean encode, Integer min) throws IOException
    {
		// проверить корректность
		if (encodable != null && encodable.str().length() < min) 
        {
            // ошибка - некорректный объект
            if (encode) throw new IllegalArgumentException(); else throw new IOException();
        }
	}
    // конструктор при раскодировании
    public VideotexString(IEncodable encodable) throws IOException
    {
        // инициализировать объект
        super(encodable); init(); 
    }
    // сериализация
    @Override protected void readObject(ObjectInputStream ois) throws IOException 
    {
        // прочитать объект
        super.readObject(ois); init(); 
    }    
    // инициализировать объект
    private void init() throws IOException
    {
        // раскодировать объект
        string = new String(content()); 
    }
    // конструктор при закодировании
    public VideotexString(String value) 
    {
        super(Tag.VIDEOTEXSTRING, value.getBytes()); string = value; 
    }
    // строка символов
    public final String str() { return string; } private String string;
}