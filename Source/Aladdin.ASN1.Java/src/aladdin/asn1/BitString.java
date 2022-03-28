package aladdin.asn1;
import java.math.*; 
import java.io.*; 
import java.util.*;
        
///////////////////////////////////////////////////////////////////////////
// Строка битов
///////////////////////////////////////////////////////////////////////////
public class BitString extends AsnObject
{
    private static final long serialVersionUID = -1240351884017526628L;

    // проверить допустимость типа
    public static boolean isValidTag(Tag tag) { return tag.equals(Tag.BITSTRING); }
    
    // проверить корректность объекта
    public static void validate(BitString encodable, 
        boolean encode, java.lang.Integer min, java.lang.Integer max) throws IOException
    {
		// проверить корректность
		if (encodable != null && encodable.bits() < min)
        {
            // ошибка - некорректный объект
            if (encode) throw new IllegalArgumentException(); else throw new IOException();
        }
		// проверить корректность
		if (encodable != null && encodable.bits() > max)
        {
            // ошибка - некорректный объект
            if (encode) throw new IllegalArgumentException(); else throw new IOException();
        }
    }
    // проверить корректность объекта
    public static void validate(BitString encodable, 
        boolean encode, java.lang.Integer min) throws IOException
    {
		// проверить корректность
		if (encodable != null && encodable.bits() < min)
        {
            // ошибка - некорректный объект
            if (encode) throw new IllegalArgumentException(); else throw new IOException();
        }
	}
	// преобразовать значение во флаги
	public static long toFlags(byte[] value, int bits)
	{ 
        // определить последний ненулевой байт
		int cb = value.length; while (cb >= 1 && value[cb - 1] == 0) cb--;

		// проверить наличие ненулевых байтов
		if (cb == 0) return 0; long numeric = 0; 

        // для всех битов ненулевого байта
		for (int i = 0; i < 8; i++)
		{
            // извлечь бит
            byte bt = (byte)((value[cb - 1] >>> i) & 0x1);

            // установить число битов
            if (bits == 0 && bt != 0) bits = 8 * cb - i;

            // изменить позицию бита
            numeric = (numeric << 1) | bt;
		}
		// для всех байтов 
		for (int i = cb - 2; i >= 0; i--)
		{
            // для всех битов
            for (int j = 0; j < 8; j++)
            {
                // извлечь бит
				byte bt = (byte)((value[i] >>> j) & 0x1);

				// изменить позицию бита
				numeric = numeric << 1 | bt;
            }
		}
        return numeric; 
    }
    // конструктор при раскодировании
    public BitString(IEncodable encodable) throws IOException
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
        // проверить корректность объекта
		if (content().length == 0) throw new IOException();

        // проверить способ кодирования строки битов
        if (pc().equals(PC.PRIMITIVE))
        {
            // проверить корректность объекта
            if (content()[0] >= 8) throw new IOException();

            // для пустого объекта
            if (content().length == 1)
            {
				// проверить корректность объекта
				if (content()[0] > 0) throw new IOException();

				// проверить на пустую строку
				value = new byte[0]; bits = 0; return;
            }
            // определить число неиспользуемых битов
            int unused = content()[0];
            
            // выделить память под строку битов
            value = new byte[content().length - 1];

            // определить число ненулевых битов 
            bits = 8 * value.length - unused;

            // скопировать строку битов
            System.arraycopy(content(), 1, value, 0, value.length);

            // обнулить неиспользуемые биты
            value[(bits - 1) / 8] &= (byte)~((1 << unused) - 1); return;
        }
		// задать начальные условия при перечислении внутренних объектов
		int length = content().length; value = new byte[0]; bits = 0;

		// для всех внутренних объектов
		for (int cb = 0; length > 0;)
		{
            // раскодировать внутренний объект
            BitString inner = new BitString(Encodable.decode(content(), cb, length));

            // проверить корректность объекта
            if ((inner.bits() % 8) != 0 && length != inner.encoded().length)
            {
                // при ошибке выбросить исключение
				throw new IOException();
            }
            // определить новый размер данных
            int resizeLength = value.length + inner.value().length; 
            
            // выделить память для переразмещенных данных
            byte[] resizeValue = new byte[resizeLength];
            
            // скопировать предыдущие данные
            System.arraycopy(value, 0, resizeValue, 0, value.length);  
            
            // добавить содержимое внутреннего объекта
            System.arraycopy(inner.value(), 0, 
                resizeValue, value.length, resizeValue.length - value.length
            );
            // увеличить число битов
            value = resizeValue; bits += inner.bits();
			
            // перейти на следующий объект
            cb += inner.encoded().length; length -= inner.encoded().length;
        }
    }
    // конструктор при закодировании
    public BitString(byte[] value) { this(value, value.length * 8); }

    // конструктор при закодировании
    public BitString(byte[] value, int bits)
    {
        super(Tag.BITSTRING);
	
        // проверить на пустую строку
		if (bits == 0) { this.value = new byte[0]; this.bits = 0; return; }

		// определить число неиспользуемых битов
		int unused = ((bits % 8) != 0) ? 8 - (bits % 8) : 0;

		// выделить память под строку битов
		this.value = new byte[(bits + 7) / 8]; this.bits = bits;

		// скопировать строку битов
		System.arraycopy(value, 0, this.value, 0, this.value.length);

		// обнулить неиспользуемые биты
        this.value[(bits - 1) / 8] &= (byte)~((1 << unused) - 1);
    }
    // конструктор при закодировании
    public BitString(BigInteger number, int bits)
    {
        // проверить корректность числа
		super(Tag.BITSTRING); if (number.signum() < 0) throw new IllegalArgumentException();
	
		// определить число неиспользуемых битов
		this.bits = bits; int unused = ((bits % 8) != 0) ? 8 - bits % 8 : 0;
		
        // получить закодированное представление
        byte[] encoded = number.shiftLeft(unused).toByteArray(); 
        
        // проверить необходимость переразмещения
        if (encoded.length == 1 || encoded[0] != 0) this.value = encoded; 

        // переразместить буфер
        else this.value = Arrays.copyOfRange(encoded, 1, encoded.length); 
    }
    // способ кодирования для DER-кодировки
    @Override protected final PC derPC() { return PC.PRIMITIVE; }

    // содержимое объекта
    @Override protected final byte[] derContent()
    {
        // выделить память для кодирования
		byte[] content = new byte[value.length + 1];

		// закодировать неиспользуемое число битов
		content[0] = (byte)(8 * value.length - bits);

		// закодировать строку битов
		System.arraycopy(value, 0, content, 1, value.length); return content;
    }
    // строка битов и их количество
    public final byte[] value() { return value; }
    public final int    bits () { return bits;  }

    // раскодировать большое число
    public final BigInteger toBigInteger()
    {
		// определить число неиспользуемых битов
		int unused = value.length * 8 - bits;

		// раскодировать большое число
		return new BigInteger(1, value).shiftRight(unused);
    }
    // строка битов и их количество
    protected byte[] value; protected int bits;
}