using System;

namespace Aladdin.CAPI.ANSI.Derive
{
    ///////////////////////////////////////////////////////////////////////////
    // Наследование ключа HKDF (RFC 5869)
    ///////////////////////////////////////////////////////////////////////////
    public class HKDF : KeyDerive
    {
	    // алгоритм HMAC
        private Mac hmacAlgorithm; private byte[] salt; 
    
	    // конструктор
	    public HKDF(Mac hmacAlgorithm) : this(hmacAlgorithm, null) {}
	    // конструктор
	    public HKDF(Mac hmacAlgorithm, byte[] salt) 
        { 
            // сохранить переданные параметры
            this.hmacAlgorithm = RefObject.AddRef(hmacAlgorithm); this.salt = salt; 
        } 
        // освободить ресурсы 
        protected override void OnDispose() 
        { 
            // освободить ресурсы 
            RefObject.Release(hmacAlgorithm); base.OnDispose();
        }
        // получить начальное значение
        protected virtual byte[] GetSalt(byte[] random)
        {
            // вернуть начальное значение
            if (salt != null) return salt; if (random == null) throw new InvalidOperationException(); 

            // раскодировать случайные данные
            ASN1.ANSI.X962.SharedInfo sharedInfo = new ASN1.ANSI.X962.SharedInfo(ASN1.Encodable.Decode(random)); 

            // указать случайные данные
            return (sharedInfo.EntityUInfo != null) ? sharedInfo.EntityUInfo.Value : null; 
        }
	    // согласовать ключ
	    public override ISecretKey DeriveKey(ISecretKey key, 
            byte[] random, SecretKeyFactory keyFactory, int deriveSize) 
	    {
            // проверить наличие размера
            if (deriveSize < 0) throw new InvalidOperationException(); 

            // проверить корректность ключа
            byte[] z = key.Value; if (z == null) throw new InvalidKeyException(); 

            // указать начальное значение
            byte[] salt = GetSalt(random); if (salt == null) salt = new byte[0];  

            // указать случайные данные
            byte[] info = random; if (info == null) info = new byte[0];

            // выделить требуемую память и определить размер хэш-значения
            byte[] KEK = new byte[deriveSize]; int hmacLen = hmacAlgorithm.MacSize;

            // указать фабрику создания ключей
            SecretKeyFactory genericFactory = SecretKeyFactory.Generic; 

            // создать ключ HMAC
            ISecretKey hmacKey = genericFactory.Create(salt); 

            // выполнить хэширование
            ISecretKey PRK = genericFactory.Create(hmacAlgorithm.MacData(hmacKey, z, 0, z.Length)); 

            // закодировать данные для хэширования
            byte[] buffer = Arrays.Concat(new byte[hmacLen], info, new byte[1]);
        
            // для каждого блока ключа шифрования ключа
            for (int i = 0, offset = hmacLen; i < (deriveSize + hmacLen - 1) / hmacLen; i++, offset = 0)
            {
                // закодировать номер блока
                buffer[buffer.Length - 1] = (byte)(i + 1); 

                // захэшировать данные
                byte[] mac = hmacAlgorithm.MacData(PRK, buffer, offset, buffer.Length - offset); 

                // скопировать часть ключа
                if (deriveSize >= (i + 1) * hmacLen) Array.Copy(mac, 0, KEK, i * hmacLen, hmacLen); 

                // скопировать часть ключа
                else Array.Copy(mac, 0, KEK, i * hmacLen, deriveSize - i * hmacLen); 
            }
            return keyFactory.Create(KEK); 
	    }
    }
}
