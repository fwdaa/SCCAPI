using System; 
using System.IO; 

namespace Aladdin.CAPI.ANSI.Wrap
{
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм шифрования ключа AES с дополнением
    ///////////////////////////////////////////////////////////////////////////
    public class AES_PAD : KeyWrap
    {
        // способ кодирования чисел
        private const Math.Endian Endian = Math.Endian.BigEndian; 
    
	    // вектор инициализации по умолчанию
	    private static readonly byte[] DefaultIV = new byte[] { 
            (byte)0xA6, (byte)0x59, (byte)0x59, (byte)0xA6 
        }; 
        // алгоритм шифрования и синхропосылка
        private CAPI.Cipher aesECB; private byte[] iv;   
    
        // конструктор 
        public AES_PAD(CAPI.Cipher aesECB, byte[] iv) 
        {
            // сохранить переданные параметры
            this.aesECB = RefObject.AddRef(aesECB); this.iv = iv;
        }
        // конструктор 
        public AES_PAD(CAPI.Cipher aesECB) : this(aesECB, DefaultIV) {}
        
        // освободить ресурсы 
        protected override void OnDispose() 
        {
            // освободить ресурсы 
            RefObject.Release(aesECB); base.OnDispose();            
        }
        // тип ключа
        public override SecretKeyFactory KeyFactory { get { return aesECB.KeyFactory; }}
        // размер ключей
        public override int[] KeySizes { get { return aesECB.KeySizes; }}

        // зашифровать ключ
	    public override byte[] Wrap(IRand rand, ISecretKey KEK, ISecretKey wrappedKey) 
	    {
		    // проверить тип ключа
		    byte[] CEK = wrappedKey.Value; if (CEK == null)
		    {
			    // при ошибке выбросить исключение
			    throw new InvalidKeyException();
		    }
		    // определить размер дополненных данных
		    int cbPadded = (CEK.Length + 7) / 8 * 8;  

		    // дополнить данные 
		    byte[] R = new byte[cbPadded]; Array.Copy(CEK, 0, R, 0, CEK.Length);
  
		    // сформировать вектор инициализации
		    byte[] A = new byte[8]; Array.Copy(iv, 0, A, 0, 4);
 
		    // закодировать размер
            Math.Convert.FromInt32(CEK.Length, Endian, A, 4);
            
            // сформировать блок для зашифрования
            if (R.Length == 8) { byte[] block = Arrays.Concat(A, R);  

                // получить преобразование зашифрования
                using (Transform encryption = aesECB.CreateEncryption(KEK, PaddingMode.None)) 
                {
                    // зашифровать блок
                    return encryption.TransformData(block, 0, block.Length); 
                }
            }
            else {
                // создать алгоритм шифрования дополненного ключа
                using (KeyWrap keyWrap = new AES(aesECB, A))
                {
                    // зашифровать ключ 
                    using (ISecretKey k = SecretKeyFactory.Generic.Create(R)) return keyWrap.Wrap(rand, KEK, k); 
                }
            }
        }
	    // расшифровать ключ
	    public override ISecretKey Unwrap(ISecretKey KEK, byte[] wrappedCEK, SecretKeyFactory keyFactory) 
	    {
		    // проверить размер ключа
		    if (wrappedCEK.Length < 16 || (wrappedCEK.Length % 8) != 0) 
		    {
			    // при ошибке выбросить исключение
			    throw new InvalidDataException();
		    }
            // получить преобразование расшифрования
            using (Transform decryption = aesECB.CreateDecryption(KEK, PaddingMode.None))
            {
                // обработать частный случай
                byte[] A; byte[] R; if (wrappedCEK.Length == 16) 
                {
                    // расшифровать блок
                    byte[] block = decryption.TransformData(wrappedCEK, 0, wrappedCEK.Length);
                
                    // разбить блок на части
                    A = new byte[8]; Array.Copy(block, 0, A, 0, 8);
                    R = new byte[8]; Array.Copy(block, 8, R, 0, 8); 
                }
                else {
                    // выделить память для переменных 
                    A = new byte[8]; R = new byte[wrappedCEK.Length - 8]; 

                    // установить начальные условия
                    Array.Copy(wrappedCEK, 0, A, 0,                     8); 
                    Array.Copy(wrappedCEK, 8, R, 0, wrappedCEK.Length - 8); 

                    // выделить память для переменных
                    byte[] block = new byte[16]; byte[] number = new byte[8];  

                    // выполнить 6 раз
                    decryption.Init(); for (int j = 5; j >= 0; j--)
                    {
                        // для всех блоков зашифровываемого ключа
                        for (int i = R.Length / 8 - 1; i >= 0; i--)
                        {
                            // определить номер шага
                            int index = (R.Length / 8 * j + i + 1); 

                            // закодировать номер шага
                            Math.Convert.FromInt64(index, Endian, number, 0);

                            // добавить номер шага
                            for (int k = 0; k < 8; k++) A[k] ^= number[k]; 

                            // создать блок для зашифрования
                            Array.Copy(A,     0, block, 0, 8);
                            Array.Copy(R, 8 * i, block, 8, 8); 

                            // расшифровать блок
                            decryption.Update(block, 0, block.Length, block, 0);

                            // разбить блок на части
                            Array.Copy(block, 0, A,     0, 8);
                            Array.Copy(block, 8, R, 8 * i, 8); 
                        }
                    }
                } 
                // проверить совпадение вектора инициализации
                if (!Arrays.Equals(A, 0, iv, 0, 4)) throw new InvalidDataException();

                // определить число байтов ключа
                int cbCEK = Math.Convert.ToInt32(A, 4, Endian); 

                // проверить корректность размера
                if (R.Length < cbCEK || cbCEK <= R.Length - 8) throw new InvalidDataException();

                // извлечь зашифрованный ключ
                return keyFactory.Create(Arrays.CopyOf(R, 0, cbCEK)); 
            }
        }
        ////////////////////////////////////////////////////////////////////////////
        // Тест известного ответа
        ////////////////////////////////////////////////////////////////////////////
        public static void Test(KeyWrap keyWrap) 
        {
            if (CAPI.KeySizes.Contains(keyWrap.KeySizes, 24))
            KnownTest(null, keyWrap, new byte[] {
                (byte)0x58, (byte)0x40, (byte)0xdf, (byte)0x6e, 
                (byte)0x29, (byte)0xb0, (byte)0x2a, (byte)0xf1, 
                (byte)0xab, (byte)0x49, (byte)0x3b, (byte)0x70, 
                (byte)0x5b, (byte)0xf1, (byte)0x6e, (byte)0xa1, 
                (byte)0xae, (byte)0x83, (byte)0x38, (byte)0xf4, 
                (byte)0xdc, (byte)0xc1, (byte)0x76, (byte)0xa8
            }, new byte[] {
                (byte)0xc3, (byte)0x7b, (byte)0x7e, (byte)0x64, 
                (byte)0x92, (byte)0x58, (byte)0x43, (byte)0x40, 
                (byte)0xbe, (byte)0xd1, (byte)0x22, (byte)0x07, 
                (byte)0x80, (byte)0x89, (byte)0x41, (byte)0x15, 
                (byte)0x50, (byte)0x68, (byte)0xf7, (byte)0x38
            }, new byte[] {
                (byte)0x13, (byte)0x8b, (byte)0xde, (byte)0xaa, 
                (byte)0x9b, (byte)0x8f, (byte)0xa7, (byte)0xfc, 
                (byte)0x61, (byte)0xf9, (byte)0x77, (byte)0x42, 
                (byte)0xe7, (byte)0x22, (byte)0x48, (byte)0xee, 
                (byte)0x5a, (byte)0xe6, (byte)0xae, (byte)0x53, 
                (byte)0x60, (byte)0xd1, (byte)0xae, (byte)0x6a,
                (byte)0x5f, (byte)0x54, (byte)0xf3, (byte)0x73, 
                (byte)0xfa, (byte)0x54, (byte)0x3b, (byte)0x6a
            });  
            if (CAPI.KeySizes.Contains(keyWrap.KeySizes, 24))
            KnownTest(null, keyWrap, new byte[] {
                (byte)0x58, (byte)0x40, (byte)0xdf, (byte)0x6e, 
                (byte)0x29, (byte)0xb0, (byte)0x2a, (byte)0xf1, 
                (byte)0xab, (byte)0x49, (byte)0x3b, (byte)0x70, 
                (byte)0x5b, (byte)0xf1, (byte)0x6e, (byte)0xa1, 
                (byte)0xae, (byte)0x83, (byte)0x38, (byte)0xf4, 
                (byte)0xdc, (byte)0xc1, (byte)0x76, (byte)0xa8
            }, new byte[] {
                (byte)0x46, (byte)0x6f, (byte)0x72, (byte)0x50, 
                (byte)0x61, (byte)0x73, (byte)0x69
            }, new byte[] {
                (byte)0xaf, (byte)0xbe, (byte)0xb0, (byte)0xf0, 
                (byte)0x7d, (byte)0xfb, (byte)0xf5, (byte)0x41, 
                (byte)0x92, (byte)0x00, (byte)0xf2, (byte)0xcc, 
                (byte)0xb5, (byte)0x0b, (byte)0xb2, (byte)0x4f
            });  
        }
    }
}
