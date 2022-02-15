using System;
using System.IO;

namespace Aladdin.CAPI.ANSI.Keyx.RSA
{
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм расшифрования RSA
    ///////////////////////////////////////////////////////////////////////////
    public class Decipherment : CAPI.Decipherment
    {
        // способ кодирования чисел
        protected const Math.Endian Endian = Math.Endian.BigEndian; 

        // расшифровать данные
        public override byte[] Decrypt(IPrivateKey privateKey, byte[] data) 
        {
            // преобразовать тип ключа
            ANSI.RSA.IPrivateKey rsaPrivateKey = (ANSI.RSA.IPrivateKey)privateKey;
        
            // вычислить максимальный размер данных
            int bits = rsaPrivateKey.Modulus.BitLength; int k = (bits + 7) / 8; 

            // проверить размер данных
            if (data.Length != k) throw new InvalidDataException(); 
            
            // расшифровать данные
            byte[] encoded = Power(rsaPrivateKey, data); 
        
            // проверить размер данных
            if (encoded.Length != k) throw new InvalidOperationException(); 
        
            // раскодировать данные
            return Decode(encoded, bits);         
        }
        // раскодировать данные
        protected virtual byte[] Decode(byte[] encoded, int bits) { return encoded; }
    
        // способ возведения в степень
        protected virtual byte[] Power(ANSI.RSA.IPrivateKey privateKey, byte[] data) 
        {
            // определить размер модуля в байтах
            int k = (privateKey.Modulus.BitLength + 7) / 8; 

            // получить значение модуля и экспоненты
            Math.BigInteger modulus  = privateKey.Modulus        ; 
            Math.BigInteger exponent = privateKey.PrivateExponent; 

            // раскодировать данные
            Math.BigInteger decoded = Math.Convert.ToBigInteger(data, Endian); 
                
            // возвести большое число в степень по модулю
            return Math.Convert.FromBigInteger(decoded.ModPow(exponent, modulus), Endian, k); 
        }
    }
}
