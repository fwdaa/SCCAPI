package aladdin.asn1;
import java.util.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Идентификатор объекта
///////////////////////////////////////////////////////////////////////////
public class ObjectIdentifier extends AsnObject
{
    private static final long serialVersionUID = 7359578378752075835L;
    
    // проверить допустимость типа
    public static boolean isValidTag(Tag tag) { return tag.equals(Tag.OBJECTIDENTIFIER); }
    
    // конструктор при раскодировании
    public ObjectIdentifier(IEncodable encodable) throws IOException
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
        StringBuilder builder = new StringBuilder();

    	// проверить корректность способа кодирования
    	if (pc() != PC.PRIMITIVE) throw new IOException();

        // проверить корректность объекта
        if (content().length == 0) throw new IOException();

		// проверить корректность объекта
		if ((content()[content().length - 1] & 0x80) != 0)
		{
            // при ошибке выбросить исключение
            throw new IOException();
        }
		// для всех байтов представления
		int count = 1;
		for (int i = 0; i < content().length; i++)
		{
            // подсчитать количество чисел идентификатора
            if ((content()[i] & 0x80) == 0) count++;
        }
		// выделить память для идентификатора
		ids = new long[count]; int cb = 0;

		// для всех чисел идентификатора
		for (int i = 1; i < count; i++)
		{
            // для всех непоследних разрядов числа
            for (; (content()[cb] & 0x80) != 0; cb++, ids[i] <<= 7)
            {
                // учесть непоследние разряды числа
				ids[i] |= content()[cb] & 0x7F;
            }
            // учесть последние разряды числа
            ids[i] |= content()[cb++] & 0xFF;
		}
		// извлечь первые два числа
	         if (ids[1] >= 80) { ids[0] = 2; ids[1] -= 80; }
        else if (ids[1] >= 40) { ids[0] = 1; ids[1] -= 40; }

		// для всех чисел идентификатора
		for (int i = 0; i < ids.length - 1; i++)
		{
            // поместить число в строку
            builder.append(String.format("%1$s.", ids[i]));
        }
		// поместить последнее число в строку
		value = builder.append(String.format("%1$s", ids[ids.length - 1])).toString();    
    }
    // конструктор при закодировании
    public ObjectIdentifier(String value)
    {
    	super(Tag.OBJECTIDENTIFIER); int pos;

        // указать начальные условия разбора строки
		ArrayList<Long> list = new ArrayList<Long>();

		// до окончания строки идентификатора
		for (int start = 0; true; start = pos + 1)
		{
            // найти позицию разделителя в строке
            pos = value.indexOf('.', start);
            if (pos >= 0)
            {
                // извлечь строку с числом идентификатора
				String substr = value.substring(start, pos);

				// проверить корректность числа
				list.add(Long.parseLong(substr));
            }
            else {
				// извлечь строку с числом идентификатора
				String substr = value.substring(start);

				// проверить корректность числа
				list.add(Long.parseLong(substr)); break;
            }
		}
        // выделить память для идентификаторов
        ids = new long[list.size()]; this.value = value; 

        // сохранить значения чисел 
        for (int i = 0; i < ids.length; i++) ids[i] = list.get(i);
    }
    // способ кодирования для DER-кодировки
    @Override protected PC derPC() { return PC.PRIMITIVE; }

    // содержимое объекта
    @Override protected byte[] derContent()
    {
        // вычислить конкатенацию первых двух чисел
		long number = ids[0] * 40 + ids[1]; int cb = 0;

		// для всех чисел идентификатора
		for (int i = 1; i < ids.length; i++, cb++)
		{
            // определить размер закодированного числа
			if (number >= 0x0100000000000000L) cb += 8; else 
			if (number >= 0x0002000000000000L) cb += 7; else 
			if (number >= 0x0000040000000000L) cb += 6; else 
			if (number >= 0x0000000800000000L) cb += 5; else 
			if (number >= 0x0000000010000000L) cb += 4; else 
			if (number >= 0x0000000000200000L) cb += 3; else 
			if (number >= 0x0000000000004000L) cb += 2; else 
			if (number >= 0x0000000000000080L) cb += 1;

             // перейти на следующее число
             if (i < ids.length - 1) number = ids[i + 1];
		}
		// выделить память для кодирования
        byte[] content = new byte[cb];

		// вычислить конкатенацию первых двух чисел
		number = ids[0] * 40 + ids[1]; cb = 0;

        // для всех чисел идентификатора
		for (int i = 1; i < ids.length; i++)
		{
			// в зависимости от величины числа
			if (number >= 0x0100000000000000L)
            {
                // закодировать часть числа
				content[cb++] = (byte)((((number & 0x7F00000000000000L) >> 56) & 0xFF) | 0x80);
            }
			// в зависимости от величины числа
			if (number >= 0x0002000000000000L)
            {
				// закодировать часть числа
				content[cb++] = (byte)((((number & 0x00FE000000000000L) >> 49) & 0xFF) | 0x80);
            }
			// в зависимости от величины числа
			if (number >= 0x0000040000000000L)
            {
				// закодировать часть числа
				content[cb++] = (byte)((((number & 0x0001FC0000000000L) >> 42) & 0xFF) | 0x80);
            }
			// в зависимости от величины числа
			if (number >= 0x0000000800000000L)
            {
				// закодировать часть числа
				content[cb++] = (byte)((((number & 0x000003F800000000L) >> 35) & 0xFF) | 0x80);
            }
			// в зависимости от величины числа
			if (number >= 0x0000000010000000L)
			{
				// закодировать часть числа
				content[cb++] = (byte)((((number & 0x00000007F0000000L) >> 28) & 0xFF) | 0x80);
			}
			// в зависимости от величины числа
			if (number >= 0x0000000000200000L)
			{
				// закодировать часть числа
				content[cb++] = (byte)((((number & 0x000000000FE00000L) >> 21) & 0xFF) | 0x80);
			}
			// в зависимости от величины числа
			if (number >= 0x0000000000004000L)
			{
				// закодировать часть числа
				content[cb++] = (byte)((((number & 0x00000000001FC000L) >> 14) & 0xFF) | 0x80);
			}
			// в зависимости от величины числа
			if (number >= 0x0000000000000080L)
			{
				// закодировать часть числа
				content[cb++] = (byte)((((number & 0x0000000000003F80L) >> 7) & 0xFF) | 0x80);
			}
            // закодировать часть числа
            content[cb++] = (byte)(number & 0x0000007F);

            // перейти на следующее число
            if (i < ids.length - 1) number = ids[i + 1];
		}
		return content;
    }
     // идентификатор объекта
    public final String value() { return value; }

    // идентификатор объекта в строковой и числовой форме
    private String value; private long[] ids;
}