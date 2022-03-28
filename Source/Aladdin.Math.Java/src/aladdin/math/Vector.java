package aladdin.math;
import java.io.*;
import java.math.*; 

///////////////////////////////////////////////////////////////////////
// Вектор (a_0, ..., a_{m-1}). Внутренее представление magnitude: 
// первое слово содержит биты [a_0, a_1, ...], последнее слово 
// содержит биты [..., a_{m-1}]. При преобразовании вектора в число 
// создаваемое число имеет вид: a_0 2^{m-1} + ... + a_{m-2} 2 + a_{m-1}.  
///////////////////////////////////////////////////////////////////////
public final class Vector implements Serializable
{
    private static final long serialVersionUID = -7213935803212489983L;
    
    // коэффициенты вектора
    private final int[] magnitude; private final int m; 

    // нулевой вектор
    public static Vector zeros(int m) { return new Vector(m); }
    // вектор из единиц
    public static Vector ones(int m) 
    {
        // создать буфер для битов
        int[] magnitude = new int[(m + 31) / 32]; 
        
        // заполнить буфер единицами
        for (int i = 0; i < magnitude.length; i++) magnitude[i] = -1;

        // очистить неиспользуемые биты
        if ((m % 32) != 0) magnitude[0] &= (1 << (m % 32)) - 1; 
        
        // вернуть вектор из единиц
        return new Vector(magnitude, m); 
    }
    // конструктор
    public Vector(java.util.Random random, int m)
    {
        // проверить наличие генератора
        if (random == null) throw new IllegalArgumentException(); 
        
        // сгенерировать случайные данные
        byte[] encoded = new byte[(m + 7) / 8]; random.nextBytes(encoded);
        
        // очистить неиспользуемые биты
        if ((m % 8) != 0) encoded[0] &= (1 << (m % 8)) - 1; 
        
        // преобразовать массив байтов в массив 32-битных слов 
        magnitude = Utils.bitsToUints(encoded, m); this.m = m; 
    }
    // конструктор
    public Vector(BigInteger value, int m)
    {
        // определить требуемый размер
        int cb = (m + 7) / 8; Endian endian = Endian.BIG_ENDIAN; 
        
        // получить закодированное представление
        byte[] encoded = Convert.fromBigInteger(value, endian, cb); 
        
        // преобразовать массив байтов в массив 32-битных слов 
        magnitude = Utils.bitsToUints(encoded, m); this.m = m; 
    }
    // конструктор
    protected Vector(int[] magnitude, int m)
    {
        // сохранить переданные параметры
        this.magnitude = magnitude; this.m = m; 
    }
    // конструктор
    private Vector(int m) { this(new int[(m + 31) / 32], m); }
    
    // преобразовать в число
    public final BigInteger toBigInteger() 
    { 
        // преобразовать массив слов в массив байтов
        byte[] encoded = Utils.uintsToBits(magnitude, m); 
        
        // раскодировать число
        return new BigInteger(1, encoded); 
    }
    // преобразовать в многочлен
    public final Polynom toPolynom() 
    { 
        // преобразовать в многочлен
        return new Polynom(magnitude.clone()); 
    }
    ///////////////////////////////////////////////////////////////////////
    // Унаследованные методы
    ///////////////////////////////////////////////////////////////////////
    @Override public boolean equals(Object other)
    {
		// проверить совпадение экземпляров
		if (other == this) return true;

		// проверить тип элемента
		if (!(other instanceof Vector)) return false;

		// сравнить значения элементов
		return equals((Vector)other);
    }
    @Override public int hashCode()
    {
		// учесть размер числа
        int hc = m; if (hc == 0) return hc;

		// учесть первое слово
		hc ^= magnitude[0]; if (magnitude.length != 1)
		{
			// учесть последнее слово
			hc ^= magnitude[magnitude.length - 1];
		}
		return hc;
    }
    ///////////////////////////////////////////////////////////////////////
    // Сравнение векторов
    ///////////////////////////////////////////////////////////////////////
    public final boolean equals(Vector other)
    {
		// сравнить размеры многочленов
		if (m != other.m) return false;
	
		// для всех коэффициентов многочлена
		for (int i = 0; i < magnitude.length; i++)
		{
            // проверить совпадение коэффициентов
            if (magnitude[i] != other.magnitude[i]) return false;
		}
		return true;
    }
    ///////////////////////////////////////////////////////////////////////
    // Свойства вектора
    ///////////////////////////////////////////////////////////////////////

    // число битов вектора
    public final int m() { return m; }
    
    // получить значение бита
    public final boolean testBit(int index) { return get(index) != 0; }

    // получить значение бита
    public final int get(int index)
    {
        // определить позицию бита
        int word = (m - 1 - index) / 32; int bit = (m - 1 - index) % 32; 
        
        // вернуть значение бита
        return ((magnitude[magnitude.length - 1 - word] & (1 << bit)) != 0) ? 1 : 0; 
    }
    ///////////////////////////////////////////////////////////////////////
    // операции над векторами
    ///////////////////////////////////////////////////////////////////////
    public final Vector rcr(int n) { return rcl(m - n); }
    public final Vector rcl(int n)
    {
        // проверить необходимость действий
        if (magnitude.length == 0) return this;  
        
    	// проверить на нулевой сдвиг
		if (n < 0) return rcr(-n); if ((n %= m) == 0) return this;

		// выделить память для результата
		int[] result = new int[magnitude.length]; int words = n / 32; n %= 32;
        
        // определить число неиспользуемых битов первого слова
        int unused = (32 - (m % 32)) % 32; int used = 32 - unused; 
         
        // для всех разрядов, извлекаемых справа 
        int i = 0; for (; i < magnitude.length - 1 - words; i++)
        {
            // выполнить соответствующие сдвиги
            result[i] = (magnitude[words + i] << n) | (magnitude[words + i + 1] >>> (32 - n));
        }
        // выполнить соответствующие сдвиги
        result[i] = (magnitude[words + i] << n) | ((magnitude[0] << unused) >>> (32 - n)); 
            
        // извлечь недостающие биты из второго слова
        if (n > used) result[i] |= magnitude[1] >>> (32 - (n - used));           

        // пересчитать величину сдвига и для оставшихся разрядов
        for (n = (n + unused) % 32, i++; i < magnitude.length; i++)
        {
            // вычислить индекс элемента
            int j = i - (magnitude.length - words); 

            // выполнить соответствующие сдвиги
            result[i] = (magnitude[j] << n) | (magnitude[j + 1] >>> (32 - n));
        }
        // удалить неиспользуемые биты
        if (unused > 0) result[0] &= (1 << used) - 1; 
        
        // вернуть реультат
        return new Vector(result, m);
    }
    public final Vector add(Vector B)
    {
        // проверить совпадение размерности
        if (B.m() != m) throw new IllegalArgumentException(); 
        
        // скопировать первый вектор
        int[] result = magnitude.clone();

		// сложить многочлены
		for (int i = 0; i < magnitude.length; i++) result[i] ^= B.magnitude[i];
		
		// вернуть многочлен
		return new Vector(result, m);
    }
    // скалярное умножение векторов
    public final int product(Vector B)
    {
        // проверить корректность 
        if (B.m() != m) throw new IllegalArgumentException(); int r = 0;
        
        // для всех слов
        for (int i = 0; i < magnitude.length; i++)
        {
            // выполнить логическую операцию
            int word = magnitude[i] & B.magnitude[i]; 
            
            // для всех битов слов
            for (int mask = 1; mask != 0; mask <<= 1)
            {
                // проверить значение бита
                if ((word & mask) != 0) r ^= 1; 
            }
        }
        return r; 
    }
    // умножение на матрицу справа
    public final Vector product(Matrix matrix)
    {
        // получить список столбцов
        Vector[] columns = matrix.columns(); 
        
        // выделить память для результата
        VectorBuilder result = new VectorBuilder(columns.length); 
        
        // для всех столбцов матрицы
        for (int i = 0; i < columns.length; i++)
        {
            // вычислить скалярное произведение
            result.set(i, product(columns[i])); 
        }
        // вернуть результат
        return result.toVector(); 
    }
}