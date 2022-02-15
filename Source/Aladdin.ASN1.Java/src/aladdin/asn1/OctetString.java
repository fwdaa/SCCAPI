package aladdin.asn1;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Строка байтов
///////////////////////////////////////////////////////////////////////////
public class OctetString extends AsnObject
{
    // проверить допустимость типа
    public static boolean isValidTag(Tag tag) { return tag.equals(Tag.OCTETSTRING); }
    
    // проверить корректность объекта
    public static void validate(OctetString encodable, 
        boolean encode, java.lang.Integer min, java.lang.Integer max) throws IOException
    {
		// проверить корректность
		if (encodable != null && encodable.value().length < min) 
        {
            // ошибка - некорректный объект
            if (encode) throw new IllegalArgumentException(); else throw new IOException();
        }
		// проверить корректность
		if (encodable != null && encodable.value().length > max) 
        {
            // ошибка - некорректный объект
            if (encode) throw new IllegalArgumentException(); else throw new IOException();
        }
    }
    // проверить корректность объекта
    public static void validate(OctetString encodable, 
        boolean encode, java.lang.Integer min) throws IOException
    {
		// проверить корректность
		if (encodable != null && encodable.value().length < min) 
        {
            // ошибка - некорректный объект
            if (encode) throw new IllegalArgumentException(); else throw new IOException();
        }
	}
    // конструктор при раскодировании
    public OctetString(IEncodable encodable) throws IOException
    {
        super(encodable);
	
        // проверить способ кодирования строки байтов
		if (encodable.pc().equals(PC.PRIMITIVE))
        { 
            // извлечь значение строки байтов
            value = encodable.content(); return;
		}
		// задать начальные условия при перечислении внутренних объектов
		int length = encodable.content().length; byte[] bytes = new byte[0];

		// для всех внутренних объектов
		for (int cb = 0; length > 0;)
		{
            // раскодировать внутренний объект
            OctetString inner = new OctetString(Encodable.decode(encodable.content(), cb, length));

             // определить новый размер данных
            int resizeLength = bytes.length + inner.value().length; 
            
            // выделить память для переразмещенных данных
            byte[] resizeValue = new byte[resizeLength];
            
            // скопировать предыдущие данные
            System.arraycopy(bytes, 0, resizeValue, 0, bytes.length);  
            
            // добавить содержимое внутреннего объекта
            System.arraycopy(inner.value(), 0, 
                resizeValue, bytes.length, resizeValue.length - bytes.length
            );
            bytes = resizeValue; 
            
            // перейти на следующий объект
            cb += inner.encoded().length; length -= inner.encoded().length;
        }
        this.value = bytes; 
    }
    // конструктор при закодировании
    protected OctetString(Tag tag, byte[] value, int ofs, int cb)
    {
    	super(tag);

        // сохранить строку байтов
		this.value = new byte[cb]; System.arraycopy(value, ofs, this.value, 0, cb);
    }
    // конструктор при закодировании
    protected OctetString(Tag tag, byte[] value)
    {
		this(tag, value, 0, value.length);
    }
    // конструктор при закодировании
    public OctetString(byte[] value, int ofs, int cb)
    {
		this(Tag.OCTETSTRING, value, ofs, cb);
    }
    // конструктор при закодировании
    public OctetString(byte[] value) { this(value, 0, value.length); }

    // способ кодирования для DER-кодировки
    @Override protected final PC derPC() { return PC.PRIMITIVE; }

    // содержимое объекта
    @Override protected byte[] derContent() { return value; }

    // строка байтов
    public final byte[] value() { return value; } protected final byte[] value;
}