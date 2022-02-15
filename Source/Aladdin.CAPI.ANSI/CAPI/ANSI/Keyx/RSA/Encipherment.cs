using System;

namespace Aladdin.CAPI.ANSI.Keyx.RSA
{
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм зашифрования RSA
    ///////////////////////////////////////////////////////////////////////////
    public class Encipherment : CAPI.Encipherment
    {
        // способ кодирования чисел
        protected const Math.Endian Endian = Math.Endian.BigEndian; 
    
        // зашифровать данные
        public override byte[] Encrypt(IPublicKey publicKey, IRand rand, byte[] data)
        {
            // преобразовать тип ключа
            ANSI.RSA.IPublicKey rsaPublicKey = (ANSI.RSA.IPublicKey)publicKey;  

            // определить размер модуля в байтах
            int bits = rsaPublicKey.Modulus.BitLength; int k = (bits + 7) / 8; 
        
            // закодировать данные
            byte[] encoded = Encode(rand, data, bits); 
        
            // проверить размер данных
            if (encoded.Length != k) throw new InvalidOperationException(); 
        
            // зашифровать данные
            byte[] encrypted = Power(rsaPublicKey, encoded); 
        
            // проверить размер данных
            if (encrypted.Length != k) throw new InvalidOperationException(); return encrypted; 
        }
        // закодировать данные
        protected virtual byte[] Encode(IRand rand, byte[] data, int bits)
        {
            // закодировать данные
            return Encoding.Encode(data, (bits + 7) / 8); 
        }
        // способ возведения в степень
        protected virtual byte[] Power(ANSI.RSA.IPublicKey publicKey, byte[] data)
        {
            // определить размер модуля в байтах
            int k = (publicKey.Modulus.BitLength + 7) / 8; 

            // получить значение модуля и экспоненты
            Math.BigInteger modulus  = publicKey.Modulus       ; 
            Math.BigInteger exponent = publicKey.PublicExponent; 

            // закодировать данные
            Math.BigInteger encoded = Math.Convert.ToBigInteger(data, Endian); 
        
            // возвести большое число в степень по модулю
            return Math.Convert.FromBigInteger(encoded.ModPow(exponent, modulus), Endian, k); 
        }
    }
}
