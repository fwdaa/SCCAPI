package aladdin.capi.ansi.keyx.rsa;

///////////////////////////////////////////////////////////////////////////
// Дополнение нулями
///////////////////////////////////////////////////////////////////////////
public class Encoding 
{
    // закодировать данные
    public static byte[] encode(byte[] data, int k)
    {
        // проверить размер данных
        if (data.length > k - 11) throw new IllegalArgumentException();

        // выделить память для результата
        byte[] encoded = new byte[k]; 

        // скопировать данные
        System.arraycopy(data, 0, encoded, k - data.length, data.length); 

        // выполнить дополнение нулями
        for (int i = 0; i < k - data.length; i++) encoded[i] = 0x00; return encoded; 
    }
}
