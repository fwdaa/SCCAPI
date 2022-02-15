package aladdin.asn1;
import java.math.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Целое число со знаком
///////////////////////////////////////////////////////////////////////////
public final class Integer extends AsnObject
{
    // проверить допустимость типа
    public static boolean isValidTag(Tag tag) { return tag.equals(Tag.INTEGER); }
    
    // проверить корректность объекта
    public static void validate(Integer encodable, boolean encode, 
        java.lang.Integer min, java.lang.Integer max) throws IOException
    {
		// проверить корректность
		if (encodable != null && encodable.value().intValue() < min) 
        {
            // ошибка - некорректный объект
            if (encode) throw new IllegalArgumentException(); else throw new IOException();
        }
		// проверить корректность
		if (encodable != null && encodable.value().intValue() > max) 
        {
            // ошибка - некорректный объект
            if (encode) throw new IllegalArgumentException(); else throw new IOException();
        }
    }
    // проверить корректность объекта
    public static void validate(Integer encodable, 
        boolean encode, java.lang.Integer min) throws IOException
    {
		// проверить корректность
		if (encodable != null && encodable.value().intValue() < min) 
        {
            // ошибка - некорректный объект
            if (encode) throw new IllegalArgumentException(); else throw new IOException();
        }
	}
    // конструктор при раскодировании
    public Integer(IEncodable encodable) throws IOException
    {
    	super(encodable);

        // проверить корректность способа кодирования
		if (encodable.pc() != PC.PRIMITIVE) throw new IOException();

		// проверить корректность объекта
		if (encodable.content().length == 0) throw new IOException();

		// раскодировать целое число со знаком
		this.value = new BigInteger(encodable.content());
    }
    // конструктор при закодировании
    public Integer(BigInteger value)
    {
        super(Tag.INTEGER); this.value = value;
    }
    // конструктор при закодировании
    public Integer(int value) { this(BigInteger.valueOf(value)); }

    // способ кодирования для DER-кодировки
    @Override protected final PC derPC() { return PC.PRIMITIVE; }

    // содержимое объекта
    @Override protected final byte[] derContent() { return value.toByteArray(); }

    // целое число со знаком
    public final BigInteger value() { return value; } private final BigInteger value;
}