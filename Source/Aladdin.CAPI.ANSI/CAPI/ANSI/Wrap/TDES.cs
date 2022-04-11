using System;
using System.IO;

namespace Aladdin.CAPI.ANSI.Wrap
{
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм шифрования ключа TDES
    ///////////////////////////////////////////////////////////////////////////
    public class TDES : KeyWrap
    {
        // блочный алгоритм шифрования 
        private IBlockCipher blockCipher; 
        // размер ключа и алгоритм хэширования
        private int keyLength; private CAPI.Hash sha1;
        
	    // вектор инициализации
	    private static readonly byte[] IV = new byte[] { 
            0x4A, 0xDD, 0xA2, 0x2C, 0x79, 0xE8, 0x21, 0x05 
        };
        // конструктор
        public TDES(IBlockCipher blockCipher, int keyLength, CAPI.Hash sha1) 
        {
            // сохранить переданные параметры
            this.blockCipher = RefObject.AddRef(blockCipher); 
            
            // сохранить переданные параметры
            this.sha1 = RefObject.AddRef(sha1); this.keyLength = keyLength; 
        }
        // освободить выделенные ресурсы
        protected override void OnDispose()
        {
            // освободить выделенные ресурсы
            RefObject.Release(sha1); RefObject.Release(blockCipher); base.OnDispose(); 
        }
        // тип ключа
        public override SecretKeyFactory KeyFactory { get 
        { 
            // проверить изменение размера 
            if (keyLength == 0) return blockCipher.KeyFactory; 
        
            // указать используемый размер
            return blockCipher.KeyFactory.Narrow(new int[] {keyLength}); 
        }}
	    // зашифровать ключ
	    public override byte[] Wrap(IRand rand, ISecretKey key, ISecretKey wrappedKey)
	    {
		    // проверить тип ключа
		    byte[] CEK = wrappedKey.Value; if (CEK == null) throw new InvalidKeyException();

		    // проверить размер ключа
		    if (CEK.Length != 24) throw new InvalidKeyException();

		    // вычислить контрольную сумму
		    byte[] ICV = sha1.HashData(CEK, 0, 24); 

		    // объединить ключ и контрольную сумму
		    byte[] CEKICV = Arrays.Concat(CEK, Arrays.CopyOf(ICV, 0, 8)); 

		    // сгенерировать случайный вектор инициализации
		    byte[] startIV = new byte[8]; rand.Generate(startIV, 0, 8);

            // создать алгоритм шифрования
            using (CAPI.Cipher cipher = blockCipher.CreateBlockMode(new CipherMode.CBC(startIV)))
            {  
                // зашифровать ключ с контрольной суммой
                CEKICV = cipher.Encrypt(key, PaddingMode.None, CEKICV, 0, CEKICV.Length); 
            }
		    // объединить вектор инициализации с зашифрованным ключом
		    byte[] IVCEKICV = Arrays.Concat(startIV, CEKICV); Array.Reverse(IVCEKICV);
             
            // создать алгоритм шифрования
            using (CAPI.Cipher cipher = blockCipher.CreateBlockMode(new CipherMode.CBC(IV)))
            {  
                // зашифровать с измененным порядком байтов
                return cipher.Encrypt(key, PaddingMode.None, IVCEKICV, 0, IVCEKICV.Length); 
            }
        }
	    // расшифровать ключ
	    public override ISecretKey Unwrap(ISecretKey key, byte[] wrappedCEK, SecretKeyFactory keyFactory)
	    {
		    // проверить размер данных
		    if (wrappedCEK.Length != 40) throw new IOException();
        
            // выделить память для синхропосылки
            byte[] startIV = new byte[8]; byte[] IVCEKICV; byte[] CEKICV; 

            // создать алгоритм шифрования
            using (CAPI.Cipher cipher = blockCipher.CreateBlockMode(new CipherMode.CBC(IV)))
            {  
                // расшифровать данные
                IVCEKICV = cipher.Decrypt(key, PaddingMode.None, wrappedCEK, 0, wrappedCEK.Length); 
            }
            // извлечь вектор инициализации
            Array.Reverse(IVCEKICV); Array.Copy(IVCEKICV, 0, startIV, 0, 8); 

            // создать алгоритм шифрования
            using (CAPI.Cipher cipher = blockCipher.CreateBlockMode(new CipherMode.CBC(startIV)))
            {  
                // расшифровать данные
                CEKICV = cipher.Decrypt(key, PaddingMode.None, IVCEKICV, 8, 32); 
            }
		    // вычислить контрольную сумму
		    byte[] ICV = sha1.HashData(CEKICV, 0, 24);
 
		    // проверить совпадение контрольных сумм
		    if (!Arrays.Equals(ICV, 0, CEKICV, 24, 8)) throw new InvalidDataException(); 

		    // вернуть вычисленный ключ
            return keyFactory.Create(Arrays.CopyOf(CEKICV, 0, 24));
	    }
        ////////////////////////////////////////////////////////////////////////////
        // Тест известного ответа
        ////////////////////////////////////////////////////////////////////////////
        public static void Test(KeyWrap keyWrap) 
        {
            byte[] random = new byte[] {
                (byte)0x5d, (byte)0xd4, (byte)0xcb, (byte)0xfc, 
                (byte)0x96, (byte)0xf5, (byte)0x45, (byte)0x3b
            }; 
            // создать генератор случайных данных
            using (CAPI.Test.Rand rand = new CAPI.Test.Rand(random)) 
            {
                // выполнить тест
                KnownTest(rand, keyWrap, new byte[] {
                    (byte)0x25, (byte)0x5e, (byte)0x0d, (byte)0x1c, 
                    (byte)0x07, (byte)0xb6, (byte)0x46, (byte)0xdf, 
                    (byte)0xb3, (byte)0x13, (byte)0x4c, (byte)0xc8,
                    (byte)0x43, (byte)0xba, (byte)0x8a, (byte)0xa7, 
                    (byte)0x1f, (byte)0x02, (byte)0x5b, (byte)0x7c, 
                    (byte)0x08, (byte)0x38, (byte)0x25, (byte)0x1f        
                }, new byte[] {
                    (byte)0x29, (byte)0x23, (byte)0xbf, (byte)0x85, 
                    (byte)0xe0, (byte)0x6d, (byte)0xd6, (byte)0xae, 
                    (byte)0x52, (byte)0x91, (byte)0x49, (byte)0xf1, 
                    (byte)0xf1, (byte)0xba, (byte)0xe9, (byte)0xea, 
                    (byte)0xb3, (byte)0xa7, (byte)0xda, (byte)0x3d, 
                    (byte)0x86, (byte)0x0d, (byte)0x3e, (byte)0x98        
                }, new byte[] {
                    (byte)0x69, (byte)0x01, (byte)0x07, (byte)0x61, 
                    (byte)0x8e, (byte)0xf0, (byte)0x92, (byte)0xb3, 
                    (byte)0xb4, (byte)0x8c, (byte)0xa1, (byte)0x79, 
                    (byte)0x6b, (byte)0x23, (byte)0x4a, (byte)0xe9, 
                    (byte)0xfa, (byte)0x33, (byte)0xeb, (byte)0xb4, 
                    (byte)0x15, (byte)0x96, (byte)0x04, (byte)0x03, 
                    (byte)0x7d, (byte)0xb5, (byte)0xd6, (byte)0xa8, 
                    (byte)0x4e, (byte)0xb3, (byte)0xaa, (byte)0xc2, 
                    (byte)0x76, (byte)0x8c, (byte)0x63, (byte)0x27, 
                    (byte)0x75, (byte)0xa4, (byte)0x67, (byte)0xd4        
                });
            }
        }
    }
}
