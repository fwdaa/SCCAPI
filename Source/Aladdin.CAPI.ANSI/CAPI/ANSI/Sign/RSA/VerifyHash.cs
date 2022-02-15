using System;
using System.IO;

namespace Aladdin.CAPI.ANSI.Sign.RSA
{
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм проверки подписи RSA
    ///////////////////////////////////////////////////////////////////////////
    public class VerifyHash : CAPI.VerifyHash
    {
        // способ кодирования чисел
        protected const Math.Endian Endian = Math.Endian.BigEndian; 
    
        // проверить подпись хэш-значения
        public override void Verify(IPublicKey publicKey, 
            ASN1.ISO.AlgorithmIdentifier hashAlgorithm, byte[] hash, byte[] signature)
        {
            // преобразовать тип ключа
            ANSI.RSA.IPublicKey rsaPublicKey = (ANSI.RSA.IPublicKey)publicKey; 

            // вычислить максимальный размер данных
            int bits = rsaPublicKey.Modulus.BitLength; int k = (bits + 7) / 8; 

            // проверить размер данных
            if (signature.Length != k) throw new InvalidDataException(); 
            
            // расшифровать данные
            byte[] encoded = Power(rsaPublicKey, signature); 
        
            // проверить размер данных
            if (encoded.Length != k) throw new InvalidOperationException(); 
        
            // проверить подпись
            Check(encoded, bits, hashAlgorithm, hash);         
        }
        // проверить подпись
        protected virtual void Check(byte[] encoded, int bits, 
            ASN1.ISO.AlgorithmIdentifier hashAlgorithm, byte[] hash)
        {
            // закодировать данные
            byte[] check = ANSI.Keyx.RSA.Encoding.Encode(hash, encoded.Length); 
        
            // проверить совпадение значений
            if (!Arrays.Equals(check, encoded)) throw new SignatureException();  
        }
        // способ возведения в степень
        protected virtual byte[] Power(ANSI.RSA.IPublicKey publicKey, byte[] signature)
        {
            // определить размер модуля в байтах
            int k = (publicKey.Modulus.BitLength + 7) / 8; 

            // получить значение модуля и экспоненты
            Math.BigInteger modulus  = publicKey.Modulus       ; 
            Math.BigInteger exponent = publicKey.PublicExponent; 

            // закодировать данные
            Math.BigInteger encoded = Math.Convert.ToBigInteger(signature, Endian); 
        
            // возвести большое число в степень по модулю
            return Math.Convert.FromBigInteger(encoded.ModPow(exponent, modulus), Endian, k); 
        }
    }
}
