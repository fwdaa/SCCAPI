package aladdin.asn1;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Строка числовых символов
///////////////////////////////////////////////////////////////////////////
public final class NumericString extends OctetString
{
    private static final long serialVersionUID = -3805270896455461779L;
    
    // проверить допустимость типа
    public static boolean isValidTag(Tag tag) { return tag.equals(Tag.NUMERICSTRING); }
    
    // проверить корректность объекта
    public static void validate(NumericString encodable, 
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
    public static void validate(NumericString encodable, 
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
    public NumericString(IEncodable encodable) throws IOException
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
        string = new String(content(), "US-ASCII"); 
    }
    // конструктор при закодировании
    public NumericString(String value) 
    {
        super(Tag.NUMERICSTRING, Utils.encodeString(value, "US-ASCII")); string = value; 
    }
    // строка символов
    public final String str() { return string; } private String string;
}