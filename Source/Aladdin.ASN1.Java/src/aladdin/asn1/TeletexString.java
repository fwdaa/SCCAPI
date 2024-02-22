package aladdin.asn1;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Строка символов Teletex
///////////////////////////////////////////////////////////////////////////
public final class TeletexString extends OctetString
{
    private static final long serialVersionUID = -4594023038640908779L;
    
    // проверить допустимость типа
    public static boolean isValidTag(Tag tag) { return tag.equals(Tag.TELETEXSTRING); }
    
    // проверить корректность объекта
    public static void validate(TeletexString encodable, 
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
    public static void validate(TeletexString encodable, 
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
    public TeletexString(IEncodable encodable) throws IOException
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
    public TeletexString(String value) 
    {
        super(Tag.TELETEXSTRING, value.getBytes()); string = value; 
    }
    // строка символов
    public final String str() { return string; } private String string;
}