using System;

namespace Aladdin.CAPI.ANSI.Derive
{
    ///////////////////////////////////////////////////////////////////////////
    // Наследование ключа SP800-108
    ///////////////////////////////////////////////////////////////////////////
    public class SP800_108 : KeyDerive
    {
        // способ кодирования чисел
        private const Math.Endian Endian = Math.Endian.BigEndian; 

	    // алгоритм хэширования
        private Mac hmacAlgorithm;
    
	    // конструктор
	    public SP800_108(Mac hmacAlgorithm) 
        { 
            // сохранить переданные параметры
            this.hmacAlgorithm = RefObject.AddRef(hmacAlgorithm); 
        } 
        // освободить ресурсы 
        protected override void OnDispose() 
        { 
            // освободить ресурсы 
            RefObject.Release(hmacAlgorithm); base.OnDispose();
        }
	    // сгенерировать блок данных
	    public override ISecretKey DeriveKey(ISecretKey key, 
            byte[] random, SecretKeyFactory keyFactory, int deriveSize) 
	    {
            // проверить наличие размера
            if (deriveSize < 0) throw new InvalidOperationException(); 
        
            // проверить корректность ключа
            byte[] z = key.Value; if (z == null) throw new InvalidKeyException(); 
        
            // проверить наличие дополнительных данных
            if (random == null) random = new byte[0]; 
        
            // выделить требуемую память и определить размер хэш-значения
            byte[] KEK = new byte[deriveSize]; int hmacLen = hmacAlgorithm.MacSize;

            // закодировать данные для хэширования
            byte[] buffer = Arrays.Concat(new byte[4], z, random, new byte[4]);
        
            // закодировать размер в битах
            Math.Convert.FromUInt32((uint)(deriveSize * 8), Endian, buffer, buffer.Length - 4);

            // для каждого блока ключа шифрования ключа
            for (uint i = 0; i < (deriveSize + hmacLen - 1) / hmacLen; i++)
            {
                // закодировать номер блока
                Math.Convert.FromUInt32(i + 1, Endian, buffer, 0);

                // захэшировать данные
                byte[] mac = hmacAlgorithm.MacData(key, buffer, 0, buffer.Length); 

                // скопировать часть ключа
                if (deriveSize >= (i + 1) * hmacLen) Array.Copy(mac, 0, KEK, i * hmacLen, hmacLen); 

                // скопировать часть ключа
                else Array.Copy(mac, 0, KEK, i * hmacLen, deriveSize - i * hmacLen); 
            }
            return keyFactory.Create(KEK); 
	    }
    }
}
