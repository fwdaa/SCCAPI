using System;
using System.IO;

namespace Aladdin.CAPI.ANSI.Keyx.RSA.OAEP
{
    ///////////////////////////////////////////////////////////////////////////
    // Кодирование EME OAEP
    ///////////////////////////////////////////////////////////////////////////
    public static class Encoding
    {
        // закодировать данные
	    public static byte[] Encode(CAPI.Hash hashAlgorithm, 
		    PRF maskAlgorithm, byte[] label, IRand rand, byte[] data, int k)
	    {
		    // определить размер хэш-значения
		    int hLen = hashAlgorithm.HashSize; byte[] encoded = new byte[k]; 

		    // проверить размер данных
		    if (data.Length > k - 2 * hLen - 2) throw new InvalidDataException();
 
		    // вычислить хэш-значение от метки
		    byte[] lHash = hashAlgorithm.HashData(label, 0, label.Length);
 
		    // создать нулевое заполнение
		    byte[] PS = new byte[k - data.Length - 2 * hLen - 2]; encoded[0] = 0x00; 

		    // создать блок данных
		    byte[] DB = Arrays.Concat(lHash, PS, new byte[] {0x01}, data); 
		
		    // сгенерировать случайное значение
		    byte[] seed = new byte[hLen]; rand.Generate(seed, 0, hLen); 
 
            // вычислить маску
            maskAlgorithm.Generate(seed, null, encoded, 1 + hLen, k - hLen - 1); 

		    // сложить блок данных с маской
		    for (int i = 0; i < k - hLen - 1; i++) DB[i] ^= encoded[1 + hLen + i]; 

		    // скопировать замаскированный блок данных
		    Array.Copy(DB, 0, encoded, 1 + hLen, k - hLen - 1); 
		
            // вычислить маску
            maskAlgorithm.Generate(DB, null, encoded, 1, hLen); 

		    // замаскировать случайное значение
		    for (int i = 0; i < hLen; i++) encoded[1 + i] ^= seed[i]; return encoded; 
	    }
        // раскодировать данные
	    public static byte[] Decode(CAPI.Hash hashAlgorithm, 
		    PRF maskAlgorithm, byte[] label, byte[] encoded)
	    {
		    // проверить значение первого байта
		    if (encoded[0] != 0) throw new InvalidDataException(); int k = encoded.Length; 

		    // определить размер хэш-значения
		    int hLen = hashAlgorithm.HashSize; byte[] seed = new byte[hLen];

		    // вычислить хэш-значение 
		    byte[] lHash = hashAlgorithm.HashData(label, 0, label.Length);
 
		    // извлечь замаскированный блок данных
		    byte[] DB = new byte[k - hLen - 1]; Array.Copy(encoded, 1 + hLen, DB, 0, k - hLen - 1);
		
            // вычислить маску
            maskAlgorithm.Generate(DB, null, seed, 0, hLen); 

		    // вычислить случайное значение
		    for (int i = 0; i < hLen; i++) seed[i] ^= encoded[1 + i]; 
		    
            // вычислить маску
            maskAlgorithm.Generate(seed, null, DB, 0, k - hLen - 1); 

		    // вычислить блок данных
		    for (int i = 0; i < k - hLen - 1; i++) DB[i] ^= encoded[1 + hLen + i]; 

		    // проверить совпадение хэш-значения
		    if (!Arrays.Equals(DB, 0, lHash, 0, hLen)) throw new InvalidDataException();

		    // пропустить нулевые байты
		    int j; for (j = hLen; j < k - hLen - 1 && DB[j] == 0; j++); 

		    // проверить корректность данных
		    if (j == k - hLen - 1 || DB[j] != 0x01) throw new InvalidDataException();

		    // выделить память для результата
		    byte[] data = new byte[k - hLen - j - 2]; 

		    // извлечь данные
		    Array.Copy(DB, j + 1, data, 0, data.Length); return data; 
	    }
    }
}
