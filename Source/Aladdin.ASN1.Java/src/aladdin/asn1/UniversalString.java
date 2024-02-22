package aladdin.asn1;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Строка символов UTF-32
///////////////////////////////////////////////////////////////////////////
public final class UniversalString extends OctetString
{
    private static final long serialVersionUID = 138201908012385007L;
    
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
        string = new String(content(), "UTF-32BE"); 
    }
    // конструктор при закодировании
    public UniversalString(String value) 
    {
        super(Tag.UNIVERSALSTRING, Utils.encodeString(value, "UTF-32BE")); string = value; 
    }
    // строка символов
    public final String str() { return string; } private String string;
}