package aladdin.math;
import java.math.*; 
import java.util.*;
import java.io.*;

///////////////////////////////////////////////////////////////////////
// Многочлен (a_0 x^m + ... + a_{m-1} x^1 + a_m). Внутренее представление
// magnitude: первое слово содержит биты [a_0, a_1, ...], последнее слово 
// содержит биты [..., a_{m-1}, a_m]. Размерность многочлена не содержится
// в классе и определяется последним ненулевым коэффициентом при наибольшей 
// степени. При преобразовании многочлена в вектор число координат вектора
// необходимо указывать для определения фиксированного размера представления 
// вектора. При преобразовании многочлена в число создаваемое число имеет 
// вид: a_0 2^m + ... + a_{m-1} 2 + a_m, т.е. в младших разрядах содержит
// коэффициенты при младших степенях. 
///////////////////////////////////////////////////////////////////////
public final class Polynom implements Serializable
{
    private static final long serialVersionUID = 4828668862967432355L;
    
    // коэффициенты многочлена от старших к младшим
    private final int[] magnitude; 

    // нулевое многочлен
    public static final Polynom ZERO = new Polynom();
    // единичный многочлен
    public static final Polynom ONE = new Polynom(new int[] {1});

    ///////////////////////////////////////////////////////////////////////
    // Создание многочлена
    ///////////////////////////////////////////////////////////////////////
    public Polynom() { magnitude = new int[0]; }

    // конструктор
    public Polynom(BigInteger value)
    {
        // получить закодированное представление
        byte[] encoded = value.toByteArray(); if (encoded[0] == 0)
        {
            // удалить незначимый байт
            encoded = Arrays.copyOfRange(encoded, 1, encoded.length);
        }
        // выполнить преобразование
        magnitude = Utils.bitsToUints(encoded, encoded.length * 8); 
    }
    // конструктор
    protected Polynom(int[] magnitude)
    {
		// пропустить незначимые старшие слова
		int i; for (i = 0; i < magnitude.length && magnitude[i] == 0; i++) {}

		// скопировать многочлен
		this.magnitude = Arrays.copyOfRange(magnitude, i, magnitude.length);
    }
    ///////////////////////////////////////////////////////////////////////
    // Свойства многочлена
    ///////////////////////////////////////////////////////////////////////
    public final BigInteger toBigInteger()
    {
        // получить закодированное представление
        byte[] encoded = Utils.uintsToBits(magnitude, magnitude.length * 32); 
        
        // раскодировать большое число
        return new BigInteger(1, encoded); 
	}
    public final Vector toVector(int bits)
    {
        // проверить корректность преобразования
        if ((bits + 31) / 32 < magnitude.length)
        {
            // при ошибке выбросить исключение
            throw new IllegalArgumentException(); 
        }
        // выделить массив требуемого размера
        int[] result = new int[(bits + 31) / 32]; 
        
		// скопировать первый многочлен
		System.arraycopy(magnitude, 0, result, 
            result.length - magnitude.length, magnitude.length
        );
        // создать вектор
        return new Vector(result, bits); 
	}
    public final int bitLength()
    {
        // определить число битов
        return Utils.bitLength(magnitude, 0, magnitude.length); 
    }
    // признак нулевого элемента
    public final boolean isZero() { return magnitude.length == 0; }

    // получить значение бита
    public final int get(int index)
    {
        // определить позицию бита
        int word = index / 32; int bit = index % 32; 
        
        // вернуть значение бита
        return ((magnitude[magnitude.length - 1 - word] & (1 << bit)) != 0) ? 1 : 0; 
    }
    ///////////////////////////////////////////////////////////////////////
    // Унаследованные методы
    ///////////////////////////////////////////////////////////////////////
    @Override public boolean equals(Object other)
    {
		// проверить совпадение экземпляров
		if (other == this) return true;

		// проверить тип элемента
		if (!(other instanceof Polynom)) return false;

		// сравнить значения элементов
		return equals((Polynom)other);
    }
    @Override public int hashCode()
    {
		// учесть размер числа
        int hc = magnitude.length; if (hc == 0) return hc;

		// учесть первое слово
		hc ^= magnitude[0]; if (magnitude.length != 1)
		{
			// учесть последнее слово
			hc ^= magnitude[magnitude.length - 1];
		}
		return hc;
    }
    ///////////////////////////////////////////////////////////////////////
    // Сравнение многочленов
    ///////////////////////////////////////////////////////////////////////
    public final boolean equals(Polynom other)
    {
		// сравнить размеры многочленов
		if (magnitude.length != other.magnitude.length) return false;
	
		// для всех коэффициентов многочлена
		for (int i = 0; i < magnitude.length; i++)
		{
            // проверить совпадение коэффициентов
            if (magnitude[i] != other.magnitude[i]) return false;
		}
		return true;
    }
    ///////////////////////////////////////////////////////////////////////
    // Логические сдвиги
    ///////////////////////////////////////////////////////////////////////
    public final Polynom shiftLeft(int n)
    {
    	// проверить на нулевой многочлен и сдвиг
		if (magnitude.length == 0 || n == 0) return this;

		// выделить память для результата
		int[] result = new int[magnitude.length + (n + 31) / 32]; 
        
		// установить старшие разряды
		n = n % 32; result[0] = magnitude[0] >>> (32 - n);

		// для всех разрядов
		for (int i = 1; i < magnitude.length; i++)
		{
			// сдвинуть соответствующие разряды
			result[i] = (magnitude[i] >>> (32 - n)) | (magnitude[i - 1] << n);
		}
		// установить младшие разряды
		result[magnitude.length] = magnitude[magnitude.length - 1] << n; 
        
        // вернуть реультат
        return new Polynom(result);
    }
    ///////////////////////////////////////////////////////////////////////
    // Сложение многочленов
    ///////////////////////////////////////////////////////////////////////
    public final Polynom add(Polynom B)
    {
		// определить размер результата
		int length = Math.max(magnitude.length, B.magnitude.length);

        // выделить память для многочлена
        int[] result = new int[length];  

		// скопировать первый многочлен
		System.arraycopy(magnitude, 0, result, 
            length - magnitude.length, magnitude.length
        );
        // сложить многочлены
		for (int i = 0; i < B.magnitude.length; i++)
		{
            result[length - B.magnitude.length + i] ^= B.magnitude[i];
		}
		// вернуть многочлен
		return new Polynom(result);
    }
    public final Polynom subtract(Polynom B) { return add(B); }

    ///////////////////////////////////////////////////////////////////////
    // Умножение многочленов
    ///////////////////////////////////////////////////////////////////////
    public final Polynom product(Polynom B)
    {
    	// для всех слов многочлена
    	Polynom R = ZERO;
        
		for (int i = 0; i < magnitude.length; i++)
		{
            // для всех битов слова
            for (int j = 1 << 31; j != 0; j >>>= 1)
            {
                // сдвинуть разряды
				R = R.shiftLeft(1);

				// проверить установку бита
				if ((magnitude[i] & j) != 0) R = R.add(B);
            }
		}
		return R;
    }
    ///////////////////////////////////////////////////////////////////////
    // Деление многочленов
    ///////////////////////////////////////////////////////////////////////
    public final Polynom[] divideAndRemainder(Polynom B)
    {
		// определить степень делителя и делимого
		int bitsB = B.bitLength(); int bitsR = bitLength();

		// проверить необходимость вычислений
		if (bitsB > bitsR) return new Polynom[] { ZERO, this }; 
        else {
            // частное и остаток
            int[] Q = new int[(bitsR - bitsB) / 32 + 1]; Polynom R = this;

            // пока остаток больше делителя
            for (; bitsR >= bitsB; bitsR = R.bitLength())
            {
				// установить бит частного
				Q[Q.length - 1 - (bitsR - bitsB) / 32] |= 1 << ((bitsR - bitsB) % 32);

				// отнять сдвинутый делитель
				R = R.add(B.shiftLeft(bitsR - bitsB));
            }
            return new Polynom[] { new Polynom(Q), R };
        }
    }
    public final Polynom divide(Polynom B)
    {
        // определить степень делителя и делимого
		int bitsB = B.bitLength(); int bitsR = bitLength();

		// проверить необходимость вычислений
		if (bitsB > bitsR) return ZERO; 

		// частное и остаток
		int[] Q = new int[(bitsR - bitsB) / 32 + 1]; Polynom R = this;

		// пока остаток больше делителя
		for (; bitsR >= bitsB; bitsR = R.bitLength())
		{
            // установить бит частного
            Q[Q.length - 1 - (bitsR - bitsB) / 32] |= 1 << ((bitsR - bitsB) % 32);

            // отнять сдвинутый делитель
            R = R.add(B.shiftLeft(bitsR - bitsB));
        }
		return new Polynom(Q);
    }
    public final Polynom remainder(Polynom B)
    {
        // определить степень делителя и делимого
		int bitsB = B.bitLength(); int bitsR = bitLength();

		// проверить необходимость вычислений
		if (bitsB > bitsR) return this; Polynom R = this;
		
		// пока остаток больше делителя
		for (; bitsR >= bitsB; bitsR = R.bitLength())
		{
            // отнять сдвинутый делитель
            R = R.add(B.shiftLeft(bitsR - bitsB));
		}
		return R;
    }
}