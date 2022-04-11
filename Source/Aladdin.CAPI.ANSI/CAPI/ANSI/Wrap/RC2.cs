using System;
using System.IO;

namespace Aladdin.CAPI.ANSI.Wrap
{
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм шифрования ключа RC2
    ///////////////////////////////////////////////////////////////////////////
    public class RC2 : KeyWrap
    {
        // блочный алгоритм шифрования 
        private IBlockCipher blockCipher; 
        // размер ключа и и алгоритм хэширования
        private int keyLength; private CAPI.Hash sha1; 

        // вектор инициализации
	    private static readonly byte[] IV = new byte[] { 
            0x4A, 0xDD, 0xA2, 0x2C, 0x79, 0xE8, 0x21, 0x05 
        };
        // конструктор
        public RC2(IBlockCipher blockCipher, int keyLength, CAPI.Hash sha1) 
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

		    // выделить память для расширения ключа
		    byte[] LCEKPAD = new byte[(CEK.Length / 8 + 1) * 8]; 
 
		    // скопировать ключ и его размер
		    LCEKPAD[0] = (byte)CEK.Length; Array.Copy(CEK, 0, LCEKPAD, 1, CEK.Length);
			
		    // сгенерировать дополнение ключа
		    rand.Generate(LCEKPAD, 1 + CEK.Length, LCEKPAD.Length - CEK.Length - 1);
 
		    // вычислить контрольную сумму
		    byte[] ICV = sha1.HashData(LCEKPAD, 0, LCEKPAD.Length);
     
		    // объединить ключ и контрольную сумму
            byte[] LCEKPADICV = Arrays.Concat(LCEKPAD, Arrays.CopyOf(ICV, 0, 8)); 

		    // сгенерировать случайный вектор инициализации
		    byte[] startIV = new byte[8]; rand.Generate(startIV, 0, 8);

            // создать алгоритм шифрования
            using (CAPI.Cipher cipher = blockCipher.CreateBlockMode(new CipherMode.CBC(startIV)))
            {  
                // зашифровать ключ с контрольной суммой
                LCEKPADICV = cipher.Encrypt(key, PaddingMode.None, LCEKPADICV, 0, LCEKPADICV.Length);
            } 
		    // объединить вектор инициализации с зашифрованным ключом
		    byte[] IVLCEKPADICV = Arrays.Concat(startIV, LCEKPADICV); Array.Reverse(IVLCEKPADICV);

            // создать алгоритм шифрования
            using (CAPI.Cipher cipher = blockCipher.CreateBlockMode(new CipherMode.CBC(IV)))
            {  
                // зашифровать с измененным порядком байтов
                return cipher.Encrypt(key, PaddingMode.None, IVLCEKPADICV, 0, IVLCEKPADICV.Length); 
            }
        }
	    // расшифровать ключ
	    public override ISecretKey Unwrap(ISecretKey key, byte[] wrappedCEK, SecretKeyFactory keyFactory)
	    {
		    // проверить размер данных
		    if ((wrappedCEK.Length % 8) != 0 || wrappedCEK.Length < 24) throw new InvalidDataException();

            // выделить память для синхропосылки
            byte[] startIV = new byte[8]; byte[] IVLCEKPADICV; byte[] LCEKPADICV; 

            // создать алгоритм шифрования
            using (CAPI.Cipher cipher = blockCipher.CreateBlockMode(new CipherMode.CBC(IV)))
            {  
                // расшифровать данные
                IVLCEKPADICV = cipher.Decrypt(key, PaddingMode.None, wrappedCEK, 0, wrappedCEK.Length); 
            }
		    // изменить порядок байтов и извлечь вектор инициализации
		    Array.Reverse(IVLCEKPADICV); Array.Copy(IVLCEKPADICV, 0, startIV, 0, 8);

            // создать алгоритм шифрования
            using (CAPI.Cipher cipher = blockCipher.CreateBlockMode(new CipherMode.CBC(startIV)))
            {  
                // расшифровать данные
                LCEKPADICV = cipher.Decrypt(key, PaddingMode.None, IVLCEKPADICV, 8, IVLCEKPADICV.Length - 8);
            } 
		    // вычислить контрольную сумму
		    byte[] ICV = sha1.HashData(LCEKPADICV, 0, LCEKPADICV.Length - 8);
 
		    // проверить совпадение контрольных сумм
		    if (!Arrays.Equals(ICV, 0, LCEKPADICV, LCEKPADICV.Length - 8, 8)) 
		    {
			    // при ошибке выбросить исключение
			    throw new InvalidDataException();
		    }
		    // выделить память для ключа
		    byte[] CEK = new byte[LCEKPADICV[0]]; 
			
		    // вернуть вычисленный ключ
		    Array.Copy(LCEKPADICV, 1, CEK, 0, CEK.Length); return keyFactory.Create(CEK); 
	    }
        ////////////////////////////////////////////////////////////////////////////
        // Тест известного ответа
        ////////////////////////////////////////////////////////////////////////////
        public static void Test40(KeyWrap keyWrap) 
        {
            byte[][] random = new byte[][] { 
               new byte[] {
                (byte)0x48, (byte)0x45, (byte)0xcc, (byte)0xe7, 
                (byte)0xfd, (byte)0x12, (byte)0x50
            }, new byte[] {
                (byte)0xc7, (byte)0xd9, (byte)0x00, (byte)0x59, 
                (byte)0xb2, (byte)0x9e, (byte)0x97, (byte)0xf7
            }}; 
            // создать генератор случайных данных
            using (CAPI.Test.Rand rand = new CAPI.Test.Rand(random)) 
            {
                // выполнить тест
                KnownTest(rand, keyWrap, new byte[] {
                    (byte)0xfd, (byte)0x04, (byte)0xfd, (byte)0x08, 
                    (byte)0x06, (byte)0x07, (byte)0x07, (byte)0xfb, 
                    (byte)0x00, (byte)0x03, (byte)0xfe, (byte)0xff, 
                    (byte)0xfd, (byte)0x02, (byte)0xfe, (byte)0x05        
                }, new byte[] {
                    (byte)0xb7, (byte)0x0a, (byte)0x25, (byte)0xfb, 
                    (byte)0xc9, (byte)0xd8, (byte)0x6a, (byte)0x86, 
                    (byte)0x05, (byte)0x0c, (byte)0xe0, (byte)0xd7, 
                    (byte)0x11, (byte)0xea, (byte)0xd4, (byte)0xd9
                }, new byte[] {
                    (byte)0x70, (byte)0xe6, (byte)0x99, (byte)0xfb, 
                    (byte)0x57, (byte)0x01, (byte)0xf7, (byte)0x83, 
                    (byte)0x33, (byte)0x30, (byte)0xfb, (byte)0x71, 
                    (byte)0xe8, (byte)0x7c, (byte)0x85, (byte)0xa4, 
                    (byte)0x20, (byte)0xbd, (byte)0xc9, (byte)0x9a, 
                    (byte)0xf0, (byte)0x5d, (byte)0x22, (byte)0xaf, 
                    (byte)0x5a, (byte)0x0e, (byte)0x48, (byte)0xd3, 
                    (byte)0x5f, (byte)0x31, (byte)0x38, (byte)0x98,
                    (byte)0x6c, (byte)0xba, (byte)0xaf, (byte)0xb4, 
                    (byte)0xb2, (byte)0x8d, (byte)0x4f, (byte)0x35            
                }); 
            }
        }
        public static void Test128(KeyWrap keyWrap)
        {
            byte[][] random = new byte[][] { 
               new byte[] {
                (byte)0x48, (byte)0x45, (byte)0xcc, (byte)0xe7, 
                (byte)0xfd, (byte)0x12, (byte)0x50
            }, new byte[] {
                (byte)0xc7, (byte)0xd9, (byte)0x00, (byte)0x59, 
                (byte)0xb2, (byte)0x9e, (byte)0x97, (byte)0xf7
            }}; 
            // создать генератор случайных данных
            using (CAPI.Test.Rand rand = new CAPI.Test.Rand(random)) 
            {
                // выполнить тест
                KnownTest(rand, keyWrap, new byte[] {
                    (byte)0xfd, (byte)0x04, (byte)0xfd, (byte)0x08, 
                    (byte)0x06, (byte)0x07, (byte)0x07, (byte)0xfb, 
                    (byte)0x00, (byte)0x03, (byte)0xfe, (byte)0xff, 
                    (byte)0xfd, (byte)0x02, (byte)0xfe, (byte)0x05        
                }, new byte[] {
                    (byte)0xb7, (byte)0x0a, (byte)0x25, (byte)0xfb, 
                    (byte)0xc9, (byte)0xd8, (byte)0x6a, (byte)0x86, 
                    (byte)0x05, (byte)0x0c, (byte)0xe0, (byte)0xd7, 
                    (byte)0x11, (byte)0xea, (byte)0xd4, (byte)0xd9
                }, new byte[] {
                    (byte)0xf4, (byte)0xd8, (byte)0x02, (byte)0x1c, 
                    (byte)0x1e, (byte)0xa4, (byte)0x63, (byte)0xd2, 
                    (byte)0x17, (byte)0xa9, (byte)0xeb, (byte)0x69, 
                    (byte)0x29, (byte)0xff, (byte)0xa5, (byte)0x77, 
                    (byte)0x36, (byte)0xd3, (byte)0xe2, (byte)0x03,
                    (byte)0x86, (byte)0xc9, (byte)0x09, (byte)0x93, 
                    (byte)0x83, (byte)0x5b, (byte)0x4b, (byte)0xe4, 
                    (byte)0xad, (byte)0x8d, (byte)0x8a, (byte)0x1b, 
                    (byte)0xc6, (byte)0x3b, (byte)0x25, (byte)0xde, 
                    (byte)0x2b, (byte)0xf7, (byte)0x79, (byte)0x93        
                }); 
            }
        }
    }
}
