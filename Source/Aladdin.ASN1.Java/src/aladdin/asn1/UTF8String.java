package aladdin.asn1;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Строка символов UTF-8
///////////////////////////////////////////////////////////////////////////
public final class UTF8String extends OctetString
{
    private static final long serialVersionUID = -3082389892162986253L;
    
    // проверить допустимость типа
    public static boolean isValidTag(Tag tag) { return tag.equals(Tag.UTF8STRING); }
    
    // проверить корректность объекта
    public static void validate(UTF8String encodable, 
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
    public static void validate(UTF8String encodable, 
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
    public UTF8String(IEncodable encodable) throws IOException
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
        string = new String(content(), "UTF-8"); 
    }
    // конструктор при закодировании
    public UTF8String(String value) 
    {
        super(Tag.UTF8STRING, Utils.encodeString(value, "UTF-8")); string = value; 
    }
    // строка символов
    public final String str() { return string; } private String string;
}