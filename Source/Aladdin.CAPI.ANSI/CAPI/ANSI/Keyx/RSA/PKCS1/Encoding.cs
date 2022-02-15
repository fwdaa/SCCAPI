using System;
using System.IO;

namespace Aladdin.CAPI.ANSI.Keyx.RSA.PKCS1
{
    ///////////////////////////////////////////////////////////////////////////
    // Кодирование EME PKCS1
    ///////////////////////////////////////////////////////////////////////////
    public static class Encoding
    {
        // закодировать данные
		public static byte[] Encode(IRand rand, byte[] data, int k)
		{
		    // проверить размер данных
		    if (data.Length > k - 11) throw new InvalidDataException();

		    // выделить память для результата
		    byte[] encoded = new byte[k]; encoded[0] = 0x00; encoded[1] = 0x02;

		    // сгенерировать случайные данные
		    rand.Generate(encoded, 2, k - data.Length - 3); 

		    // для всех сгенерированных данных
		    for (int i = 2; i < k - data.Length - 1; i++)
		    {
			    // удостовериться что байт ненулевой
			    while (encoded[i] == 0) rand.Generate(encoded, i, 1);
		    }
		    // скопировать данные
		    Array.Copy(data, 0, encoded, k - data.Length, data.Length); 
		
		    // записать значение разделителя
		    encoded[k - data.Length - 1] = 0x00; return encoded; 
		}
        // раскодировать данные
		public static byte[] Decode(byte[] encoded)
		{
		    // проверить первые байты
		    if (encoded[0] != 0 || encoded[1] != 2) throw new InvalidDataException();

		    // найти нулевой байт
		    int i; for (i = 2; i < encoded.Length && encoded[i] != 0; i++); 

		    // проверить наличие нулевого байта
		    if (i == encoded.Length) throw new InvalidDataException();

		    // выделить память для результата
		    byte[] data = new byte[encoded.Length - i - 1]; 

		    // извлечь данные
		    Array.Copy(encoded, i + 1, data, 0, data.Length); return data; 
		}
    }
}
