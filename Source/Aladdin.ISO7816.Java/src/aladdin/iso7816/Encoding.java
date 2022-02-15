package aladdin.iso7816;
import java.io.*; 

public abstract class Encoding
{
    ///////////////////////////////////////////////////////////////////////
    // Кодирование цифр
    ///////////////////////////////////////////////////////////////////////
    public static byte[] encodeDigits(int[] digits)
    {
        // выделить буфер требуемого размера
        byte[] encoded = new byte[(digits.length + 1) / 2]; 

        // закодировать цифры
        encodeDigits(digits, encoded, 0); return encoded; 
    }
    public static void encodeDigits(int[] digits, byte[] encoded, int offset)
    {
        // проверить достаточность буфера
        if (offset + (digits.length + 1) / 2 > encoded.length) throw new IllegalArgumentException(); 

        // для всех байтов
        for (int i = 0; i < digits.length / 2; i++)
        {
            // закодировать две цифры
            encoded[offset + i] = (byte)((digits[i * 2] << 4) | digits[i * 2 + 1]); 
        }
        // при наличии одной цифры в конце
        if ((digits.length % 2) != 0)
        {
            // закодировать одну цифру
            encoded[offset + digits.length / 2] = (byte)((digits[digits.length - 1] << 4) | 0x0F); 
        }
    }
    // раскодировать цифры
    public static int[] decodeDigits(int count, byte[] encoded, int offset) throws IOException
    {
        // проверить достаточность буфера
        if (offset + (count + 1) / 2 > encoded.length) throw new IOException(); 

        // выделить буфер для цифр
        int[] digits = new int[count]; 

        // для всех байтов
        for (int i = 0; i < digits.length / 2; i++)
        {
            // раскодировать две цифры
            digits[2 * i + 0] = (encoded[offset + i] >>> 4) & 0x0F; 
            digits[2 * i + 1] = (encoded[offset + i]      ) & 0x0F; 

            // проверить корректность данных
            if (digits[2 * i + 0] > 9) throw new IOException(); 
            if (digits[2 * i + 1] > 9) throw new IOException(); 
        }
        // при наличии одной цифры в конце
        if ((digits.length % 2) != 0)
        {
            // раскодировать цифру
            digits[digits.length - 1] = (encoded[offset + digits.length / 2] >>> 4) & 0x0F; 

            // проверить корректность данных
            if (digits[digits.length - 1] > 9) throw new IOException(); 
        }
        return digits; 
    }
}
