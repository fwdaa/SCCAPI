package aladdin.capi.ansi.keyx.rsa.pkcs1;
import aladdin.capi.*;
import java.io.*;

///////////////////////////////////////////////////////////////////////////
// Кодирование EME PKCS1
///////////////////////////////////////////////////////////////////////////
public class Encoding
{
    // закодировать данные
    public static byte[] encode(IRand rand, byte[] data, int k) throws IOException
    {
        // проверить размер данных
        if (data.length > k - 11) throw new IllegalArgumentException();

        // выделить память для результата
        byte[] encoded = new byte[k]; encoded[0] = 0x00; encoded[1] = 0x02;

        // сгенерировать случайные данные
        rand.generate(encoded, 2, k - data.length - 3); 

        // для всех сгенерированных данных
        for (int i = 2; i < k - data.length - 1; i++)
        {
            // удостовериться что байт ненулевой
            while (encoded[i] == 0) rand.generate(encoded, i, 1);
        }
        // скопировать данные
        System.arraycopy(data, 0, encoded, k - data.length, data.length); 

        // записать значение разделителя
        encoded[k - data.length - 1] = 0x00; return encoded; 
    }
    // раскодировать данные
    public static byte[] decode(byte[] encoded) throws IOException
    {
        // проверить первые байты
        if (encoded[0] != 0 || encoded[1] != 2) throw new IOException();

        // найти нулевой байт
        int i; for (i = 2; i < encoded.length && encoded[i] != 0; i++) {} 

        // проверить наличие нулевого байта
        if (i == encoded.length) throw new IOException();

        // выделить память для результата
        byte[] data = new byte[encoded.length - i - 1]; 

        // извлечь данные
        System.arraycopy(encoded, i + 1, data, 0, data.length); return data; 
    }
}
