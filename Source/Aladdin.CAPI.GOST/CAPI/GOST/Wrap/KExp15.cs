using System;
using System.IO;

namespace Aladdin.CAPI.GOST.Wrap
{
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм шифрования ключа KExp15
    ///////////////////////////////////////////////////////////////////////////
    public class KExp15 : KeyWrap
    {
        // алгоритм шифрования и алгоритм вычисления имитовставки
        private CAPI.Cipher cipher; private Mac macAlgorithm; private byte[] iv; 
    
        // создать алгоритм шифрования ключа
        public static KExp15 Create(CAPI.Factory factory, SecurityStore scope, string oid, byte[] iv)
        {
            int blockSize = 0; 
        
            // указать идентификатор алгоритма шифрования
            if (oid == ASN1.GOST.OID.gostR3412_64_wrap_kexp15 ) blockSize =  8; else 
            if (oid == ASN1.GOST.OID.gostR3412_128_wrap_kexp15) blockSize = 16; else return null; 
        
            // создать блочный алгоритм шифрования
            using (IBlockCipher blockCipher = Cipher.GOSTR3412.Create(factory, scope, blockSize))
            {
                // проверить наличие алгоритма
                if (blockCipher == null) return null; 

                // указать параметры режима
                CipherMode.CTR ctrParameters = new CipherMode.CTR(iv, blockSize); 

                // создать режим CTR
                using (CAPI.Cipher cipher = blockCipher.CreateBlockMode(ctrParameters))
                {
                    // указать начальную синхропосылку
                    byte[] start = new byte[blockSize]; 
                
                    // создать алгоритм вычисления имитовставки
                    using (Mac macAlgorithm = CAPI.MAC.OMAC1.Create(blockCipher, start, blockSize))
                    {
                        // проверить наличие алгоритма
                        if (macAlgorithm == null) return null; 
                    
                        // вернуть алгоритм шифрования ключа
                        return new KExp15(cipher, macAlgorithm, iv); 
                    }
                }
            }
        }
        // конструктор
        public KExp15(CAPI.Cipher cipher, Mac macAlgorithm, byte[] iv)
        {
            // проверить корректность размера
            if (iv.Length != cipher.BlockSize / 2) throw new ArgumentException(); 
        
            // сохранить переданные параметры
            this.cipher = RefObject.AddRef(cipher); this.iv = iv; 

            // сохранить переданные параметры
            this.macAlgorithm = RefObject.AddRef(macAlgorithm); 
        }
        // освободить выделенные ресурсы
        protected override void OnDispose() 
        { 
            // освободить выделенные ресурсы
            RefObject.Release(macAlgorithm); 

            // освободить выделенные ресурсы
            RefObject.Release(cipher); base.OnDispose();         
        } 
        // размер используемого ключа
        public override int[] KeySizes { get { return new int[] { 64 }; } }
    
	    // зашифровать ключ
	    public override byte[] Wrap(IRand rand, ISecretKey key, ISecretKey CEK) 
        {
            // проверить наличие значения ключа
            byte[] keyValue = key.Value; if (keyValue == null) throw new InvalidKeyException(); 
                
            // выделить память для значений ключей
            byte[] key1 = new byte[keyValue.Length / 2]; byte[] key2 = new byte[keyValue.Length / 2];

            // скопировать значения ключей
            Array.Copy(keyValue,           0, key1, 0, key1.Length);
            Array.Copy(keyValue, key1.Length, key2, 0, key2.Length);
        
            // проверить наличие значения 
            byte[] value = CEK.Value; if (value == null) throw new InvalidKeyException(); 
        
            // выделить буфер для вычисления имитовставки
            byte[] iv_key = new byte[iv.Length + value.Length]; 
        
            // скопировать синхропосылку и значение ключа
            Array.Copy(iv   , 0, iv_key,         0,    iv.Length);
            Array.Copy(value, 0, iv_key, iv.Length, value.Length);
        
            // создать ключ для вычисления имитовставки
            using (ISecretKey macKey = macAlgorithm.KeyFactory.Create(key1))
            {
                // вычислить имитовставку
                byte[] mac = macAlgorithm.MacData(macKey, iv_key, 0, iv_key.Length); 

                // выделить буфер для вычисления имитовставки
                byte[] key_mac = new byte[value.Length + mac.Length]; 
        
                // скопировать значение ключа и имитовставку
                Array.Copy(value, 0, key_mac,            0, value.Length);
                Array.Copy(mac  , 0, key_mac, value.Length,   mac.Length);
            
                // создать ключ для шифрования
                using (ISecretKey cipherKey = cipher.KeyFactory.Create(key2))
                {
                    // зашифровать данные
                    return cipher.Encrypt(cipherKey, PaddingMode.None, key_mac, 0, key_mac.Length); 
                }
            }
        }
	    // расшифровать ключ
	    public override ISecretKey Unwrap(ISecretKey key, byte[] wrappedCEK, SecretKeyFactory keyFactory)
        {
            // проверить наличие значения ключа
            byte[] keyValue = key.Value; if (keyValue == null) throw new InvalidKeyException(); 
                
            // выделить память для значений ключей
            byte[] key1 = new byte[keyValue.Length / 2]; byte[] key2 = new byte[keyValue.Length / 2];

            // скопировать значения ключей
            Array.Copy(keyValue,           0, key1, 0, key1.Length);
            Array.Copy(keyValue, key1.Length, key2, 0, key2.Length);
        
            // создать ключ для шифрования
            using (ISecretKey cipherKey = cipher.KeyFactory.Create(key2))
            {
                // расшифровать данные
                byte[] key_mac = cipher.Decrypt(cipherKey, 
                    PaddingMode.None, wrappedCEK, 0, wrappedCEK.Length
                ); 
                // выделить буфер для имитовставки
                byte[] check = new byte[macAlgorithm.MacSize]; 
            
                // проверить размер данных
                if (key_mac.Length < check.Length) throw new InvalidDataException(); 
            
                // выделить память для значения ключа
                byte[] value = new byte[key_mac.Length - check.Length]; 
            
                // извлечь значение ключа и имитовставку
                Array.Copy(key_mac,            0, value, 0, value.Length);
                Array.Copy(key_mac, value.Length, check, 0, check.Length);
            
                // выделить буфер для вычисления имитовставки
                byte[] iv_key = new byte[iv.Length + value.Length]; 
            
                // скопировать синхропосылку и значение ключа
                Array.Copy(   iv, 0, iv_key,         0,    iv.Length);
                Array.Copy(value, 0, iv_key, iv.Length, value.Length);
            
                // создать ключ для вычисления имитовставки
                using (ISecretKey macKey = macAlgorithm.KeyFactory.Create(key1))
                {
                    // вычислить имитовставку
                    byte[] mac = macAlgorithm.MacData(macKey, iv_key, 0, iv_key.Length); 
                
                    // проверить совпадение имитовставок
                    if (!Arrays.Equals(mac, check)) throw new InvalidDataException(); 
                }
                // вернуть значение ключа
                return keyFactory.Create(value); 
            }
        }
    }
}
