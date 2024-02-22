package aladdin.asn1;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Булевое значение
///////////////////////////////////////////////////////////////////////////
public final class Boolean extends AsnObject
{
    private static final long serialVersionUID = 5029530852418640069L;
    
    // проверить допустимость типа
    public static boolean isValidTag(Tag tag) { return tag.equals(Tag.BOOLEAN); }
    
    // булевы значения 
    public static Boolean TRUE  = new Boolean(true );
    public static Boolean FALSE = new Boolean(false);

    // конструктор при раскодировании
    public Boolean(IEncodable encodable) throws IOException
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
        // проверить корректность способа кодирования
		if (pc() != PC.PRIMITIVE) throw new IOException();

		// проверить корректность объекта
		if (content().length != 1) throw new IOException();

		// сохранить булевое значение
		this.value = (content()[0] != 0);
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
    public final boolean value() { return value; } private boolean value;
}