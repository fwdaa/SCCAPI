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
        public static KExp15 Create(CAPI.Factory factory, SecurityStore scope, int blockSize, byte[] iv)
        {
            // создать режим шифрования CTR
            using (CAPI.Cipher cipher = Cipher.GOSTR3412.CreateCTR(factory, scope, blockSize, iv))
            {
                // проверить наличие алгоритма
                if (cipher == null) return null; 
            
                // создать имитовставку OMAC
                using (Mac macAlgorithm = Cipher.GOSTR3412.CreateOMAC(
                    factory, scope, blockSize, blockSize))
                {
                    // проверить наличие алгоритма
                    if (macAlgorithm == null) return null; 
            
                    // вернуть алгоритм шифрования ключа
                    return new KExp15(cipher, macAlgorithm, iv); 
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
        // тип ключа
        public override SecretKeyFactory KeyFactory 
        { 
            // тип ключа
            get { return new SecretKeyFactory(new int[] { 64 }); } 
        }
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
        ////////////////////////////////////////////////////////////////////////////
        // Тест известного ответа
        ////////////////////////////////////////////////////////////////////////////
        public static void Test(CAPI.Factory factory, SecurityStore scope, int blockSize)
        {
            byte[] KEK = new byte[] {
                (byte)0x08, (byte)0x09, (byte)0x0A, (byte)0x0B, 
                (byte)0x0C, (byte)0x0D, (byte)0x0E, (byte)0x0F, 
                (byte)0x00, (byte)0x01, (byte)0x02, (byte)0x03, 
                (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07, 
                (byte)0x10, (byte)0x11, (byte)0x12, (byte)0x13, 
                (byte)0x14, (byte)0x15, (byte)0x16, (byte)0x17, 
                (byte)0x18, (byte)0x19, (byte)0x1A, (byte)0x1B, 
                (byte)0x1C, (byte)0x1D, (byte)0x1E, (byte)0x1F, 
                (byte)0x20, (byte)0x21, (byte)0x22, (byte)0x23, 
                (byte)0x24, (byte)0x25, (byte)0x26, (byte)0x27, 
                (byte)0x28, (byte)0x29, (byte)0x2A, (byte)0x2B, 
                (byte)0x2C, (byte)0x2D, (byte)0x2E, (byte)0x2F, 
                (byte)0x38, (byte)0x39, (byte)0x3A, (byte)0x3B, 
                (byte)0x3C, (byte)0x3D, (byte)0x3E, (byte)0x3F, 
                (byte)0x30, (byte)0x31, (byte)0x32, (byte)0x33, 
                (byte)0x34, (byte)0x35, (byte)0x36, (byte)0x37            
            };
            byte[] CEK = new byte[] {
                (byte)0x88, (byte)0x99, (byte)0xAA, (byte)0xBB, 
                (byte)0xCC, (byte)0xDD, (byte)0xEE, (byte)0xFF, 
                (byte)0x00, (byte)0x11, (byte)0x22, (byte)0x33, 
                (byte)0x44, (byte)0x55, (byte)0x66, (byte)0x77, 
                (byte)0xFE, (byte)0xDC, (byte)0xBA, (byte)0x98, 
                (byte)0x76, (byte)0x54, (byte)0x32, (byte)0x10, 
                (byte)0x01, (byte)0x23, (byte)0x45, (byte)0x67, 
                (byte)0x89, (byte)0xAB, (byte)0xCD, (byte)0xEF 
            };
            if (blockSize == 8)
            {
                byte[] iv = new byte[] { 
                    (byte)0x67, (byte)0xBE, (byte)0xD6, (byte)0x54 
                }; 
                // вывести сообщение
                CAPI.Test.Dump("IV", iv);
            
                using (KeyWrap keyWrap = Create(factory, scope, blockSize, iv))
                {
                    KnownTest(null, keyWrap, KEK, CEK, new byte[] {
                        (byte)0xCF, (byte)0xD5, (byte)0xA1, (byte)0x2D, 
                        (byte)0x5B, (byte)0x81, (byte)0xB6, (byte)0xE1, 
                        (byte)0xE9, (byte)0x9C, (byte)0x91, (byte)0x6D, 
                        (byte)0x07, (byte)0x90, (byte)0x0C, (byte)0x6A, 
                        (byte)0xC1, (byte)0x27, (byte)0x03, (byte)0xFB, 
                        (byte)0x3A, (byte)0xBD, (byte)0xED, (byte)0x55, 
                        (byte)0x56, (byte)0x7B, (byte)0xF3, (byte)0x74, 
                        (byte)0x2C, (byte)0x89, (byte)0x9C, (byte)0x75, 
                        (byte)0x5D, (byte)0xAF, (byte)0xE7, (byte)0xB4, 
                        (byte)0x2E, (byte)0x3A, (byte)0x8B, (byte)0xD9, 
                    }); 
                }
            }
            if (blockSize == 16)
            {
                byte[] iv = new byte[] { 
                    (byte)0x09, (byte)0x09, (byte)0x47, (byte)0x2D, 
                    (byte)0xD9, (byte)0xF2, (byte)0x6B, (byte)0xE8, 
                }; 
                // вывести сообщение
                CAPI.Test.Dump("IV", iv);
            
                using (KeyWrap keyWrap = Create(factory, scope, blockSize, iv))
                {
                    KnownTest(null, keyWrap, KEK, CEK, new byte[] {
                        (byte)0xE3, (byte)0x61, (byte)0x84, (byte)0xE8, 
                        (byte)0x4E, (byte)0x8D, (byte)0x73, (byte)0x6F, 
                        (byte)0xF3, (byte)0x6C, (byte)0xC2, (byte)0xE5, 
                        (byte)0xAE, (byte)0x06, (byte)0x5D, (byte)0xC6, 
                        (byte)0x56, (byte)0xB2, (byte)0x3C, (byte)0x20, 
                        (byte)0xF5, (byte)0x49, (byte)0xB0, (byte)0x2F, 
                        (byte)0xDF, (byte)0xF8, (byte)0x8E, (byte)0x1F, 
                        (byte)0x3F, (byte)0x30, (byte)0xD8, (byte)0xC2, 
                        (byte)0x9A, (byte)0x53, (byte)0xF3, (byte)0xCA, 
                        (byte)0x55, (byte)0x4D, (byte)0xBA, (byte)0xD8, 
                        (byte)0x0D, (byte)0xE1, (byte)0x52, (byte)0xB9, 
                        (byte)0xA4, (byte)0x62, (byte)0x5B, (byte)0x32, 
                    }); 
                }
            }
        }
    }
}
