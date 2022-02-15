using System;
using System.IO;

namespace Aladdin.CAPI.ANSI.Sign.RSA.PKCS1
{
    ///////////////////////////////////////////////////////////////////////////
    // Кодирование EMSA PKCS1
    ///////////////////////////////////////////////////////////////////////////
    public static class Encoding
    {
        // закодировать данные
	    public static byte[] Encode(byte[] data, int emLen)
	    {
		    // проверить размер данных
		    if (data.Length > emLen - 11) throw new InvalidDataException();

		    // выделить память для результата
		    byte[] encoded = new byte[emLen]; encoded[0] = 0x00; encoded[1] = 0x01;

		    // установить специальное заполнение
		    for (int i = 2; i < emLen - data.Length - 1; i++) encoded[i] = 0xFF; 

		    // скопировать данные
		    Array.Copy(data, 0, encoded, emLen - data.Length, data.Length); 
			
		    // записать значение разделителя
		    encoded[emLen - data.Length - 1] = 0x00; return encoded; 
	    }
    }
}
