package aladdin.capi.ansi.keyx.rsa.oaep;
import aladdin.capi.*;
import aladdin.util.*; 
import java.io.*;
import java.util.Arrays;

///////////////////////////////////////////////////////////////////////////
// Кодирование EME OAEP
///////////////////////////////////////////////////////////////////////////
public class Encoding
{
    // закодировать данные
    public static byte[] encode(Hash hashAlgorithm, 
        PRF maskAlgorithm, byte[] label, IRand rand, byte[] data, int k) throws IOException
    {
        // определить размер хэш-значения
        int hLen = hashAlgorithm.hashSize(); byte[] encoded = new byte[k]; 

        // проверить размер данных
        if (data.length > k - 2 * hLen - 2) throw new IllegalArgumentException();

        // вычислить хэш-значение от метки
        byte[] lHash = hashAlgorithm.hashData(label, 0, label.length);

        // создать нулевое заполнение
        byte[] PS = new byte[k - data.length - 2 * hLen - 2]; encoded[0] = 0x00; 

        // создать блок данных
        byte[] DB = Array.concat(lHash, PS, new byte[] {0x01}, data); 

        // сгенерировать случайное значение
        byte[] seed = new byte[hLen]; rand.generate(seed, 0, hLen); 
        
        // вычислить маску
        maskAlgorithm.generate(seed, null, encoded, 1 + hLen, k - hLen - 1);  
        
        // сложить блок данных с маской
        for (int i = 0; i < k - hLen - 1; i++) DB[i] ^= encoded[1 + hLen + i]; 

        // скопировать замаскированный блок данных
        System.arraycopy(DB, 0, encoded, 1 + hLen, k - hLen - 1); 
        
        // вычислить маску
        maskAlgorithm.generate(DB, null, encoded, 1, hLen);   
        
        // замаскировать случайное значение
        for (int i = 0; i < hLen; i++) encoded[1 + i] ^= seed[i]; return encoded; 
    }
    // раскодировать данные
    public static byte[] decode(Hash hashAlgorithm, 
        PRF maskAlgorithm, byte[] label, byte[] encoded) throws IOException
    {
        // проверить значение первого байта
        if (encoded[0] != 0) throw new IOException(); int k = encoded.length;

        // определить размер хэш-значения
        int hLen = hashAlgorithm.hashSize(); byte[] seed = new byte[hLen];

        // вычислить хэш-значение 
        byte[] lHash = hashAlgorithm.hashData(label, 0, label.length);

        // извлечь замаскированный блок данных
        byte[] DB = new byte[k - hLen - 1]; System.arraycopy(encoded, 1 + hLen, DB, 0, k - hLen - 1);
        
        // вычислить маску
        maskAlgorithm.generate(DB, null, seed, 0, hLen); 
        
        // вычислить случайное значение
        for (int i = 0; i < hLen; i++) seed[i] ^= encoded[1 + i]; 

        // вычислить маску
        maskAlgorithm.generate(seed, null, DB, 0, k - hLen - 1);  
        
        // вычислить блок данных
        for (int i = 0; i < k - hLen - 1; i++) DB[i] ^= encoded[1 + hLen + i]; 

        // проверить совпадение хэш-значения
        if (!Array.equals(DB, 0, lHash, 0, hLen)) throw new IOException();

        // пропустить нулевые байты
        int j; for (j = hLen; j < k - hLen - 1 && DB[j] == 0; j++) {} 

        // проверить корректность данных
        if (j == k - hLen - 1 || DB[j] != 0x01) throw new IOException();

        // выделить память для результата
        byte[] data = new byte[k - hLen - j - 2]; 

        // извлечь данные
        System.arraycopy(DB, j + 1, data, 0, data.length); return data; 
    }
}
