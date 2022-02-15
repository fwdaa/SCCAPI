package aladdin.math;
import java.io.*; 

public final class Utils 
{
    ///////////////////////////////////////////////////////////////////////
    // Разрядность числа в битах
    ///////////////////////////////////////////////////////////////////////
    public static int bitLength(int value)
    {
        // проверить частный случай
        if (value == 0) return 0; int bits = 32; 

        // для всех битов
        for (int i = 1 << 31; i != 0; bits--, i >>>= 1)
        {
            // проверить установку бита
            if ((value & i) != 0) break; 
        }
        return bits; 
    }
    public static int bitLength(int[] magnitude, int offset, int length)
    {
		// для всех слов
		for (int i = offset; i < offset + length; i++)
		{
            // пропустить незначимые слова
            if (magnitude[i] == 0) continue; 

            // число битов за исключением старшего слова
            int bitLength = 32 * (offset + length - i - 1);

            // учесть число битов в старшем слове
            return bitLength + Utils.bitLength(magnitude[i]);
		}
		return 0;
    }
    ///////////////////////////////////////////////////////////////////////
    // Преобразование массива байтов в массив 32-битных слов 
    ///////////////////////////////////////////////////////////////////////
    public static int[] bitsToUints(byte[] bytes, int uintBits)
    {
		// пропустить незначимые байты
		int i = 0; while (i < bytes.length && bytes[i] == 0) i++; 
        
        // определить значимый размер в байтах
        int cb = bytes.length - i; if (cb > (uintBits + 7) / 8) 
        { 
            // пропустить старшие биты
            i += (cb - (uintBits + 7) / 8); cb = (uintBits + 7) / 8; 
        }
        // выделить массив для слов 
        int[] magnitude = new int[(uintBits + 31) / 32]; 
        
        // вычислить смещение значимых слов
        int j = magnitude.length - (cb + 3) / 4; if (cb == 0) return magnitude; 
            
        // число значимых байтов старшего слова
        int count = ((cb % 4) != 0) ? (cb % 4) : 4;
        
        // извлечь значение первого байта
        magnitude[j] = bytes[i++] & 0xFF; 
        
        // обнулить незначимые биты
        if (8 * cb > uintBits) magnitude[j] &= ((1 << (uintBits % 8)) - 1); 
            
        // для всех байтов массива
        while (i < bytes.length)
        {
            // проверить заполнение слова
            if (--count == 0) { count = 4; j++; } 

            // пересчитать значение слова
            magnitude[j] <<= 8; magnitude[j] |= bytes[i++] & 0xFF;
        }
        return magnitude;
    }
    ///////////////////////////////////////////////////////////////////////
    // Преобразование массива 32-битных слов в массив байтов
    ///////////////////////////////////////////////////////////////////////
    public static byte[] uintsToBits(int[] magnitude, int uintBits)
    {
		// выделить массив требуемого размера
		int j = (uintBits + 7) / 8; byte[] bytes = new byte[j]; int i;

		// для всех слов большого числа
		for (i = magnitude.length - 1; j >= 4; i--)
		{
            // скопировать слово в формате big endian
            bytes[--j] = (byte)((magnitude[i]       ) & 0xFF);
            bytes[--j] = (byte)((magnitude[i] >>>  8) & 0xFF);
            bytes[--j] = (byte)((magnitude[i] >>> 16) & 0xFF);
            bytes[--j] = (byte)((magnitude[i] >>> 24) & 0xFF);
		}
		// прочитать старшее слово
		if (j > 0) { int value = magnitude[i];

            // для всех значимых байтов слова
            for (; j > 0; value >>>= 8)
            {
                // скопировать значимый байт
                bytes[--j] = (byte)(value & 0xFF);
            }
        }
        return bytes; 
    }
}
