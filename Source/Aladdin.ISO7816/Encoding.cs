using System;
using System.IO;

namespace Aladdin.ISO7816
{
    public static class Encoding
    {
        ///////////////////////////////////////////////////////////////////////
        // Кодирование цифр
        ///////////////////////////////////////////////////////////////////////
        public static byte[] EncodeDigits(int[] digits)
        {
            // выделить буфер требуемого размера
            byte[] encoded = new byte[(digits.Length + 1) / 2]; 

            // закодировать цифры
            EncodeDigits(digits, encoded, 0); return encoded; 
        }
        public static void EncodeDigits(int[] digits, byte[] encoded, int offset)
        {
            // проверить достаточность буфера
            if (offset + (digits.Length + 1) / 2 > encoded.Length) throw new ArgumentException(); 

            // для всех байтов
            for (int i = 0; i < digits.Length / 2; i++)
            {
                // закодировать две цифры
                encoded[offset + i] = (byte)((digits[i * 2] << 4) | digits[i * 2 + 1]); 
            }
            // при наличии одной цифры в конце
            if ((digits.Length % 2) != 0)
            {
                // закодировать одну цифру
                encoded[offset + digits.Length / 2] = (byte)((digits[digits.Length - 1] << 4) | 0x0F); 
            }
        }
        // раскодировать цифры
        public static int[] DecodeDigits(int count, byte[] encoded, int offset)
        {
            // проверить достаточность буфера
            if (offset + (count + 1) / 2 > encoded.Length) throw new InvalidDataException(); 

            // выделить буфер для цифр
            int[] digits = new int[count]; 

            // для всех байтов
            for (int i = 0; i < digits.Length / 2; i++)
            {
                // раскодировать две цифры
                digits[2 * i + 0] = encoded[offset + i] >> 4; 
                digits[2 * i + 1] = encoded[offset + i] & 15; 

                // проверить корректность данных
                if (digits[2 * i + 0] > 9) throw new InvalidDataException(); 
                if (digits[2 * i + 1] > 9) throw new InvalidDataException(); 
            }
            // при наличии одной цифры в конце
            if ((digits.Length % 2) != 0)
            {
                // раскодировать цифру
                digits[digits.Length - 1] = encoded[offset + digits.Length / 2] >> 4; 

                // проверить корректность данных
                if (digits[digits.Length - 1] > 9) throw new InvalidDataException(); 
            }
            return digits; 
        }
    }
}
