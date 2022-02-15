package aladdin.capi.ansi.sign.rsa.pss;
import aladdin.capi.*; 
import aladdin.util.*; 
import java.security.*; 
import java.io.*; 
import java.util.*; 

///////////////////////////////////////////////////////////////////////////
// Кодирование EMSA PSS
///////////////////////////////////////////////////////////////////////////
public class Encoding
{
    public static byte[] encode(IRand rand, Hash hashAlgorithm, PRF maskAlgorithm, 
        byte trailerField, int emBits, int sLength, byte[] hash) throws IOException
    {
        // сгенерировать случайные данные
        byte[] salt = new byte[sLength]; rand.generate(salt, 0, salt.length); 
                
        // объединить данные последующего хэширования
        byte[] M = Array.concat(new byte[8], hash, salt); 

        // вычислить хэш-значение
        byte[] H = hashAlgorithm.hashData(M, 0, M.length); 

        // определить размер хэш-значения и salt-значения
        int hLen = H.length; int sLen = salt.length; int emLen = (emBits + 7) / 8;
        
        // проверить корректность данных
        if (hLen > emLen - sLen - 2) throw new IllegalArgumentException();

        // создать нулевое дополнение
        byte[] PS = new byte[emLen - sLen - hLen - 2]; byte[] encoded = new byte[emLen]; 

        // создать блок данных 
        byte[] DB = Array.concat(PS, new byte[] {0x01}, salt);   
        
        // вычислить маску
        maskAlgorithm.generate(H, null, encoded, 0, emLen - hLen - 1); 
        
        // скопировать хэш-значение
        System.arraycopy(H, 0, encoded, emLen - hLen - 1, hLen); 

        // замаскировать блок данных
        for (int i = 0; i < emLen - hLen - 1; i++) encoded[i] ^= DB[i]; 

        // обнулить неиспользуемые биты
        if ((emBits % 8) != 0) encoded[0] &= (byte)((1 << (emBits % 8)) - 1);  

        // установить значение завершителя
        encoded[emLen - 1] = trailerField; return encoded; 
    }
    public static void decode(Hash hashAlgorithm, PRF maskAlgorithm, 
        byte trailerField, byte[] encoded, int emBits, int sLen, byte[] hash) 
        throws SignatureException, IOException
    {
        // определить размер хэш-значения
        int hLen = hashAlgorithm.hashSize(); int emLen = (emBits + 7) / 8;

        // выделить память для salt-значения и хэш-значения
        byte[] salt = new byte[sLen]; byte[] H = new byte[hLen]; 
        
        // проверить корректность неиспользуемых битов
        if ((emBits % 8) != 0 && (encoded[0] & ~((1 << (emBits % 8)) - 1)) != 0) 
        {
            // выбросить исключение
            throw new IOException(); 
        }
        // проверить наличие завершителя
        if (encoded[emLen - 1] != trailerField)  throw new IOException(); 
        
        // извлечь хэш-значение 
        System.arraycopy(encoded, emLen - hLen - 1, H, 0, hLen); 
        
        // выделить буфер для маски
        byte[] DB = new byte[emLen - hLen - 1]; 
        
        // вычислить маску
        maskAlgorithm.generate(H, null, DB, 0,emLen - hLen - 1); 
        
        // наложить маску
        for (int i = 0; i < emLen - hLen - 1; i++) DB[i] ^= encoded[i]; 

        // обнулить неиспользуемые биты
        if ((emBits % 8) != 0) DB[0] &= (byte)((1 << (emBits % 8)) - 1); 

        // проверить наличие нулевых байтов
        for (int i = 0; i < emLen - hLen - sLen - 2; i++) 
        {
            // проверить наличие нулевых байтов
            if (DB[i] != 0) throw new IOException(); 
        }
        // проверить наличие разделителя
        if (DB[emLen - hLen - sLen - 2] != 0x01) throw new IOException();
        
        // извлечь salt-значение
        System.arraycopy(DB, emLen - sLen - hLen - 1, salt, 0, sLen); 
        
        // объединить данные последующего хэширования
        byte[] M = Array.concat(new byte[8], hash, salt); 
                
        // вычислить хэш-значение
        byte[] check = hashAlgorithm.hashData(M, 0, M.length); 

        // сравнить хэш-значения
        if (!Arrays.equals(H, check)) throw new SignatureException(); 
    }
}
