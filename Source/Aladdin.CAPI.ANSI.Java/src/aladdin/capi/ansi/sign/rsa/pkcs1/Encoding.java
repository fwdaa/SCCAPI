package aladdin.capi.ansi.sign.rsa.pkcs1;

///////////////////////////////////////////////////////////////////////////
// Кодирование EMSA PKCS1
///////////////////////////////////////////////////////////////////////////
public class Encoding
{
    public static byte[] encode(byte[] data, int emLen)
    {
        // проверить размер данных
        if (data.length > emLen - 11) throw new IllegalArgumentException();

        // выделить память для результата
        byte[] encoded = new byte[emLen]; encoded[0] = 0x00; encoded[1] = 0x01;

        // установить специальное заполнение
        for (int i = 2; i < emLen - data.length - 1; i++) encoded[i] = (byte)0xFF; 

        // скопировать данные
        System.arraycopy(data, 0, encoded, emLen - data.length, data.length); 

        // записать значение разделителя
        encoded[emLen - data.length - 1] = 0x00; return encoded; 
    }
}
