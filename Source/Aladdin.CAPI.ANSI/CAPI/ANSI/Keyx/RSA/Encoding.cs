using System;

namespace Aladdin.CAPI.ANSI.Keyx.RSA
{
    ///////////////////////////////////////////////////////////////////////////
    // Дополнение нулями
    ///////////////////////////////////////////////////////////////////////////
    public static class Encoding 
    {
        // закодировать данные
        public static byte[] Encode(byte[] data, int k)
        {
            // проверить размер данных
            if (data.Length > k - 11) throw new ArgumentException();

            // выделить память для результата
            byte[] encoded = new byte[k]; 

            // скопировать данные
            Array.Copy(data, 0, encoded, k - data.Length, data.Length); 

            // выполнить дополнение нулями
            for (int i = 0; i < k - data.Length; i++) encoded[i] = 0x00; return encoded; 
        }
    }
}
