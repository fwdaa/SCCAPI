package aladdin.asn1;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Булевое значение
///////////////////////////////////////////////////////////////////////////
public final class Boolean extends AsnObject
{
    // проверить допустимость типа
    public static boolean isValidTag(Tag tag) { return tag.equals(Tag.BOOLEAN); }
    
    // булевы значения 
    public static Boolean TRUE  = new Boolean(true );
    public static Boolean FALSE = new Boolean(false);

    // конструктор при раскодировании
    public Boolean(IEncodable encodable) throws IOException
    {
    	super(encodable);

        // проверить корректность способа кодирования
		if (encodable.pc() != PC.PRIMITIVE) throw new IOException();

		// проверить корректность объекта
		if (encodable.content().length != 1) throw new IOException();

		// сохранить булевое значение
		this.value = (encodable.content()[0] != 0);
    }
    // конструктор при закодировании
    public Boolean(boolean value) { super(Tag.BOOLEAN); this.value = value; }

    // способ кодирования для DER-кодировки
    @Override protected final PC derPC() { return PC.PRIMITIVE; }

    // содержимое объекта
    @Override protected final byte[] derContent()
    {
		// вернуть содержимое объекта
		return new byte[] { value ? (byte)0xFF : (byte)0x00 };
    }
    // булевое значение
    public final boolean value() { return value; } private final boolean value;
}