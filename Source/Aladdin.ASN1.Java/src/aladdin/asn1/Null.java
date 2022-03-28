package aladdin.asn1;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Пустое значение
///////////////////////////////////////////////////////////////////////////
public final class Null extends AsnObject
{
    private static final long serialVersionUID = -3024807687587783254L;
    
    // проверить допустимость типа
    public static boolean isValidTag(Tag tag) { return tag.equals(Tag.NULL); }
    
    // экземпляр объекта
    public static Null INSTANCE = new Null();

    // конструктор при раскодировании
    public Null(IEncodable encodable) throws IOException
    {
    	super(encodable);

		// проверить корректность способа кодирования
		if (encodable.pc() != PC.PRIMITIVE) throw new IOException();

		// проверить корректность объекта
		if (encodable.content().length != 0) throw new IOException();
    }
    // конструктор при закодировании
    public Null() { super(Tag.NULL); }

    // способ кодирования для DER-кодировки
    @Override protected final PC derPC() { return PC.PRIMITIVE; }

    // содержимое объекта
    @Override protected final byte[] derContent() { return new byte[0]; }
}