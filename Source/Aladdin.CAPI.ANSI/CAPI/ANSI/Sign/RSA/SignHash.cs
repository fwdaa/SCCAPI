using System;

namespace Aladdin.CAPI.ANSI.Sign.RSA
{
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм подписи RSA
    ///////////////////////////////////////////////////////////////////////////
    public class SignHash : CAPI.SignHash
    {
        // способ кодирования чисел
        protected const Math.Endian Endian = Math.Endian.BigEndian; 
    
        // подписать хэш-значение
        public override byte[] Sign(IPrivateKey privateKey, IRand rand, 
            ASN1.ISO.AlgorithmIdentifier hashAlgorithm, byte[] hash)
        {
            // преобразовать тип ключа
            ANSI.RSA.IPrivateKey rsaPrivateKey = (ANSI.RSA.IPrivateKey)privateKey; 

            // определить размер модуля в байтах
            int bits = rsaPrivateKey.Modulus.BitLength; int k = (bits + 7) / 8;  
        
            // закодировать данные
            byte[] encoded = Encode(rand, hashAlgorithm, hash, bits); 
        
            // проверить размер данных
            if (encoded.Length != k) throw new InvalidOperationException(); 
        
            // зашифровать данные
            byte[] encrypted = Power(rsaPrivateKey, rand, encoded); 
        
            // проверить размер данных
            if (encrypted.Length != k) throw new InvalidOperationException(); return encrypted; 
        }
        // закодировать данные
        protected virtual byte[] Encode(IRand rand, 
            ASN1.ISO.AlgorithmIdentifier hashAlgorithm, byte[] data, int bits)
        {
            // закодировать данные
            return ANSI.Keyx.RSA.Encoding.Encode(data, (bits + 7) / 8); 
        }
        // способ возведения в степень
        protected virtual byte[] Power(ANSI.RSA.IPrivateKey privateKey, IRand rand, byte[] hash)
        {
            // определить размер модуля в байтах
            int k = (privateKey.Modulus.BitLength + 7) / 8; 

            // получить значение модуля и экспоненты
            Math.BigInteger modulus  = privateKey.Modulus        ; 
            Math.BigInteger exponent = privateKey.PrivateExponent; 

            // закодировать данные
            Math.BigInteger encoded = Math.Convert.ToBigInteger(hash, Endian); 
        
            // возвести большое число в степень по модулю
            return Math.Convert.FromBigInteger(encoded.ModPow(exponent, modulus), Endian, k); 
        }
    }
}
