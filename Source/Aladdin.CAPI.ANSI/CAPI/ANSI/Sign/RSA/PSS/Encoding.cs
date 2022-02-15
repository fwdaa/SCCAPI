using System;
using System.IO;

namespace Aladdin.CAPI.ANSI.Sign.RSA.PSS
{
    ///////////////////////////////////////////////////////////////////////////
    // Кодирование EMSA PSS
    ///////////////////////////////////////////////////////////////////////////
    public static class Encoding
    {
	    public static byte[] Encode(IRand rand, CAPI.Hash hashAlgorithm, 
            PRF maskAlgorithm, byte trailerField, int emBits, int sLen, byte[] hash)
	    {
            // сгенерировать случайные данные
            byte[] salt = new byte[sLen]; rand.Generate(salt, 0, sLen); 
                
            // объединить данные последующего хэширования
            byte[] M = Arrays.Concat(new byte[8], hash, salt); 

            // вычислить хэш-значение
            byte[] H = hashAlgorithm.HashData(M, 0, M.Length); 

		    // определить размер хэш-значения
		    int hLen = H.Length; int emLen = (emBits + 7) / 8;

            // проверить корректность параметров
            if (sLen + hLen + 2 > emLen) throw new InvalidDataException(); 

		    // создать нулевое дополнение
		    byte[] PS = new byte[emLen - sLen - hLen - 2]; byte[] encoded = new byte[emLen]; 

		    // создать блок данных 
		    byte[] DB = Arrays.Concat(PS, new byte[] {0x01}, salt);   

            // вычислить маску
	        maskAlgorithm.Generate(H, null, encoded, 0, emLen - hLen - 1); 

    	    // скопировать хэш-значение
		    Array.Copy(H, 0, encoded, emLen - hLen - 1, hLen); 

		    // замаскировать блок данных
		    for (int i = 0; i < emLen - hLen - 1; i++) encoded[i] ^= DB[i]; 

		    // обнулить неиспользуемые биты
		    if ((emBits % 8) != 0) encoded[0] &= (byte)((1 << (emBits % 8)) - 1);  

		    // установить значение завершителя
		    encoded[emLen - 1] = trailerField; return encoded; 
	    }
	    public static void Decode(CAPI.Hash hashAlgorithm, PRF maskAlgorithm, 
		    byte trailerField, byte[] encoded, int emBits, int sLen, byte[] hash)
	    {
		    // определить размер хэш-значения
		    int hLen = hashAlgorithm.HashSize; int emLen = (emBits + 7) / 8;

		    // проверить корректность неиспользуемых битов
		    if ((emBits % 8) != 0 && (encoded[0] & ~((1 << (emBits % 8)) - 1)) != 0)
            {
                // выбросить исключение
                throw new InvalidDataException(); 
            }
		    // проверить наличие завершителя
		    if (encoded[emLen - 1] != trailerField) throw new InvalidDataException();

            // выделить память для salt-значения и хэш-значения
            byte[] salt = new byte[sLen]; byte[] H = new byte[hLen]; 

		    // извлечь хэш-значение 
		    Array.Copy(encoded, emLen - hLen - 1, H, 0, hLen); 
 
            // выделить буфе для маски
            byte[] DB = new byte[emLen - hLen - 1]; 
            
	        // вычислить маску
	        maskAlgorithm.Generate(H, null, DB, 0, emLen - hLen - 1); 
            
		    // вычислить блок данных
		    for (int i = 0; i < emLen - hLen - 1; i++) DB[i] ^= encoded[i]; 

		    // обнулить неиспользуемые биты
		    if ((emBits % 8) != 0) DB[0] &= (byte)((1 << (emBits % 8)) - 1); 

		    // проверить наличие нулевых байтов
		    for (int i = 0; i < emLen - hLen - sLen - 2; i++) 
            {
		        // проверить наличие нулевых байтов
                if (DB[i] != 0) throw new InvalidDataException();
            }
		    // проверить наличие разделителя
		    if (DB[emLen - hLen - sLen - 2] != 0x01) throw new InvalidDataException();

		    // извлечь salt-значение
		    Array.Copy(DB, emLen - sLen - hLen - 1, salt, 0, sLen); 

            // объединить данные последующего хэширования
            byte[] M = Arrays.Concat(new byte[8], hash, salt); 
                
            // вычислить хэш-значение
            byte[] check = hashAlgorithm.HashData(M, 0, M.Length); 

            // сравнить хэш-значения
            if (!Arrays.Equals(H, check)) throw new SignatureException(); 
	    }
    }
}
