using System;

namespace Aladdin.CAPI.ANSI.Derive
{
    ///////////////////////////////////////////////////////////////////////////
    // Наследование ключа X.963
    ///////////////////////////////////////////////////////////////////////////
    public class X963KDF : KeyDerive
    {
        // способ кодирования чисел
        private const Math.Endian Endian = Math.Endian.BigEndian; 

	    // алгоритм хэширования
        private CAPI.Hash hashAlgorithm;
    
	    // конструктор
	    public X963KDF(CAPI.Hash hashAlgorithm) 
        { 
            // сохранить переданные параметры
            this.hashAlgorithm = RefObject.AddRef(hashAlgorithm); 
        } 
        // освободить ресурсы 
        protected override void OnDispose() 
        { 
            // освободить ресурсы 
            RefObject.Release(hashAlgorithm); base.OnDispose();
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
            byte[] KEK = new byte[deriveSize]; int hashLen = hashAlgorithm.HashSize;

            // закодировать данные для хэширования
            byte[] buffer = Arrays.Concat(z, new byte[4], random);
        
            // для каждого блока ключа шифрования ключа
            for (uint i = 0; i < (deriveSize + hashLen - 1) / hashLen; i++)
            {
                // закодировать номер блока
                Math.Convert.FromUInt32(i + 1, Endian, buffer, z.Length);

                // захэшировать данные
                byte[] hash = hashAlgorithm.HashData(buffer, 0, buffer.Length); 

                // скопировать часть ключа
                if (deriveSize >= (i + 1) * hashLen) Array.Copy(hash, 0, KEK, i * hashLen, hashLen); 

                // скопировать часть ключа
                else Array.Copy(hash, 0, KEK, i * hashLen, deriveSize - i * hashLen); 
            }
            return keyFactory.Create(KEK); 
	    }
    }
}
