using System; 

namespace Aladdin.CAPI.ANSI.Engine
{
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм шифрования DES
    ///////////////////////////////////////////////////////////////////////////
    public class DES : CAPI.Cipher
    {
        // способ кодирования чисел
        private const Math.Endian Endian = Math.Endian.BigEndian; 

        // нормализация ключа DES
        public static void AdjustKeyParity(byte[] key, int offset, int length)
        {
            // для всех байтов ключа
            for (int i = 0; i < length; i++)
            {
                // для вех битов
                int ones = 0; for (int j = 0; j < 8; j++)
                {
                    // определить число установленных битов
                    if ((key[i + offset] & (0x1 << j)) != 0) ones++;
                }
                // число установленных битов должно быть нечетным
                if((ones % 2) == 0) key[i + offset] ^= 0x01;
            }
        } 
        // тип ключа
        public override SecretKeyFactory KeyFactory { get { return Keys.DES.Instance; }}
        // размер блока
		public override int BlockSize { get { return 8; }}

		// алгоритм зашифрования блока данных
		protected override Transform CreateEncryption(ISecretKey key) 
		{
		    // проверить тип ключа
		    byte[] value = key.Value; if (value == null)
		    {
			    // при ошибке выбросить исключение
			    throw new InvalidKeyException();
		    }
            // проверить размер ключа
            if (value.Length != 8) throw new InvalidKeyException(); 
        
		    // вернуть алгоритм зашифрования блока данных
		    return new Encryption(key); 
		}
		// алгоритм расшифрования блока данных
		protected override Transform CreateDecryption(ISecretKey key)
		{
		    // проверить тип ключа
		    byte[] value = key.Value; if (value == null)
		    {
			    // при ошибке выбросить исключение
			    throw new InvalidKeyException();
		    }
            // проверить размер ключа
            if (value.Length != 8) throw new InvalidKeyException(); 
        
		    // вернуть алгоритм расшифрования блока данных
		    return new Decryption(key);
		}
	    ///////////////////////////////////////////////////////////////////////////
	    // Алгоритм зашифрования блока
	    ///////////////////////////////////////////////////////////////////////////
        public class Encryption : BlockTransform
	    {
		    // расписание ключей
		    private uint[] keys;

		    // Конструктор
		    public Encryption(ISecretKey key) : base(8)
		    { 
			    // проверить тип ключа
			    if (key.Value == null) throw new InvalidKeyException();

                // создать расписание ключей
                keys = GetKeys(key.Value, true); 
            }
		    // обработка одного блока данных
		    protected override void Update(byte[] src, int srcOff, byte[] dest, int destOff)
		    {
                DesFunc(keys, src, srcOff, dest, destOff); 
            }
	    }
	    ///////////////////////////////////////////////////////////////////////////
	    // Алгоритм расшифрования блока
	    ///////////////////////////////////////////////////////////////////////////
        public class Decryption : BlockTransform
	    {
		    // расписание ключей
		    private uint[] keys;

		    // Конструктор
		    public Decryption(ISecretKey key) : base(8)
		    { 
			    // проверить тип ключа
			    if (key.Value == null) throw new InvalidKeyException();

                // создать расписание ключей
                keys = GetKeys(key.Value, false); 
            }
		    // обработка одного блока данных
		    protected override void Update(byte[] src, int srcOff, byte[] dest, int destOff)
		    {
                DesFunc(keys, src, srcOff, dest, destOff); 
		    }
	    }
	    ///////////////////////////////////////////////////////////////////////////
	    // Вспомогательные таблицы
	    ///////////////////////////////////////////////////////////////////////////
        private static readonly uint[] SP1 = {
            0x01010400, 0x00000000, 0x00010000, 0x01010404,
            0x01010004, 0x00010404, 0x00000004, 0x00010000,
            0x00000400, 0x01010400, 0x01010404, 0x00000400,
            0x01000404, 0x01010004, 0x01000000, 0x00000004,
            0x00000404, 0x01000400, 0x01000400, 0x00010400,
            0x00010400, 0x01010000, 0x01010000, 0x01000404,
            0x00010004, 0x01000004, 0x01000004, 0x00010004,
            0x00000000, 0x00000404, 0x00010404, 0x01000000,
            0x00010000, 0x01010404, 0x00000004, 0x01010000,
            0x01010400, 0x01000000, 0x01000000, 0x00000400,
            0x01010004, 0x00010000, 0x00010400, 0x01000004,
            0x00000400, 0x00000004, 0x01000404, 0x00010404,
            0x01010404, 0x00010004, 0x01010000, 0x01000404,
            0x01000004, 0x00000404, 0x00010404, 0x01010400,
            0x00000404, 0x01000400, 0x01000400, 0x00000000,
            0x00010004, 0x00010400, 0x00000000, 0x01010004
        };
        private static readonly uint[] SP2 = {
            0x80108020, 0x80008000, 0x00008000, 0x00108020,
            0x00100000, 0x00000020, 0x80100020, 0x80008020,
            0x80000020, 0x80108020, 0x80108000, 0x80000000,
            0x80008000, 0x00100000, 0x00000020, 0x80100020,
            0x00108000, 0x00100020, 0x80008020, 0x00000000,
            0x80000000, 0x00008000, 0x00108020, 0x80100000,
            0x00100020, 0x80000020, 0x00000000, 0x00108000,
            0x00008020, 0x80108000, 0x80100000, 0x00008020,
            0x00000000, 0x00108020, 0x80100020, 0x00100000,
            0x80008020, 0x80100000, 0x80108000, 0x00008000,
            0x80100000, 0x80008000, 0x00000020, 0x80108020,
            0x00108020, 0x00000020, 0x00008000, 0x80000000,
            0x00008020, 0x80108000, 0x00100000, 0x80000020,
            0x00100020, 0x80008020, 0x80000020, 0x00100020,
            0x00108000, 0x00000000, 0x80008000, 0x00008020,
            0x80000000, 0x80100020, 0x80108020, 0x00108000
        };
        private static readonly uint[] SP3 = {
            0x00000208, 0x08020200, 0x00000000, 0x08020008,
            0x08000200, 0x00000000, 0x00020208, 0x08000200,
            0x00020008, 0x08000008, 0x08000008, 0x00020000,
            0x08020208, 0x00020008, 0x08020000, 0x00000208,
            0x08000000, 0x00000008, 0x08020200, 0x00000200,
            0x00020200, 0x08020000, 0x08020008, 0x00020208,
            0x08000208, 0x00020200, 0x00020000, 0x08000208,
            0x00000008, 0x08020208, 0x00000200, 0x08000000,
            0x08020200, 0x08000000, 0x00020008, 0x00000208,
            0x00020000, 0x08020200, 0x08000200, 0x00000000,
            0x00000200, 0x00020008, 0x08020208, 0x08000200,
            0x08000008, 0x00000200, 0x00000000, 0x08020008,
            0x08000208, 0x00020000, 0x08000000, 0x08020208,
            0x00000008, 0x00020208, 0x00020200, 0x08000008,
            0x08020000, 0x08000208, 0x00000208, 0x08020000,
            0x00020208, 0x00000008, 0x08020008, 0x00020200
        };
        private static readonly uint[] SP4 = {
            0x00802001, 0x00002081, 0x00002081, 0x00000080,
            0x00802080, 0x00800081, 0x00800001, 0x00002001,
            0x00000000, 0x00802000, 0x00802000, 0x00802081,
            0x00000081, 0x00000000, 0x00800080, 0x00800001,
            0x00000001, 0x00002000, 0x00800000, 0x00802001,
            0x00000080, 0x00800000, 0x00002001, 0x00002080,
            0x00800081, 0x00000001, 0x00002080, 0x00800080,
            0x00002000, 0x00802080, 0x00802081, 0x00000081,
            0x00800080, 0x00800001, 0x00802000, 0x00802081,
            0x00000081, 0x00000000, 0x00000000, 0x00802000,
            0x00002080, 0x00800080, 0x00800081, 0x00000001,
            0x00802001, 0x00002081, 0x00002081, 0x00000080,
            0x00802081, 0x00000081, 0x00000001, 0x00002000,
            0x00800001, 0x00002001, 0x00802080, 0x00800081,
            0x00002001, 0x00002080, 0x00800000, 0x00802001,
            0x00000080, 0x00800000, 0x00002000, 0x00802080
        };
        private static readonly uint[] SP5 = {
            0x00000100, 0x02080100, 0x02080000, 0x42000100,
            0x00080000, 0x00000100, 0x40000000, 0x02080000,
            0x40080100, 0x00080000, 0x02000100, 0x40080100,
            0x42000100, 0x42080000, 0x00080100, 0x40000000,
            0x02000000, 0x40080000, 0x40080000, 0x00000000,
            0x40000100, 0x42080100, 0x42080100, 0x02000100,
            0x42080000, 0x40000100, 0x00000000, 0x42000000,
            0x02080100, 0x02000000, 0x42000000, 0x00080100,
            0x00080000, 0x42000100, 0x00000100, 0x02000000,
            0x40000000, 0x02080000, 0x42000100, 0x40080100,
            0x02000100, 0x40000000, 0x42080000, 0x02080100,
            0x40080100, 0x00000100, 0x02000000, 0x42080000,
            0x42080100, 0x00080100, 0x42000000, 0x42080100,
            0x02080000, 0x00000000, 0x40080000, 0x42000000,
            0x00080100, 0x02000100, 0x40000100, 0x00080000,
            0x00000000, 0x40080000, 0x02080100, 0x40000100
        };
        private static readonly uint[] SP6 = {
            0x20000010, 0x20400000, 0x00004000, 0x20404010,
            0x20400000, 0x00000010, 0x20404010, 0x00400000,
            0x20004000, 0x00404010, 0x00400000, 0x20000010,
            0x00400010, 0x20004000, 0x20000000, 0x00004010,
            0x00000000, 0x00400010, 0x20004010, 0x00004000,
            0x00404000, 0x20004010, 0x00000010, 0x20400010,
            0x20400010, 0x00000000, 0x00404010, 0x20404000,
            0x00004010, 0x00404000, 0x20404000, 0x20000000,
            0x20004000, 0x00000010, 0x20400010, 0x00404000,
            0x20404010, 0x00400000, 0x00004010, 0x20000010,
            0x00400000, 0x20004000, 0x20000000, 0x00004010,
            0x20000010, 0x20404010, 0x00404000, 0x20400000,
            0x00404010, 0x20404000, 0x00000000, 0x20400010,
            0x00000010, 0x00004000, 0x20400000, 0x00404010,
            0x00004000, 0x00400010, 0x20004010, 0x00000000,
            0x20404000, 0x20000000, 0x00400010, 0x20004010
        };
        private static readonly uint[] SP7 = {
            0x00200000, 0x04200002, 0x04000802, 0x00000000,
            0x00000800, 0x04000802, 0x00200802, 0x04200800,
            0x04200802, 0x00200000, 0x00000000, 0x04000002,
            0x00000002, 0x04000000, 0x04200002, 0x00000802,
            0x04000800, 0x00200802, 0x00200002, 0x04000800,
            0x04000002, 0x04200000, 0x04200800, 0x00200002,
            0x04200000, 0x00000800, 0x00000802, 0x04200802,
            0x00200800, 0x00000002, 0x04000000, 0x00200800,
            0x04000000, 0x00200800, 0x00200000, 0x04000802,
            0x04000802, 0x04200002, 0x04200002, 0x00000002,
            0x00200002, 0x04000000, 0x04000800, 0x00200000,
            0x04200800, 0x00000802, 0x00200802, 0x04200800,
            0x00000802, 0x04000002, 0x04200802, 0x04200000,
            0x00200800, 0x00000000, 0x00000002, 0x04200802,
            0x00000000, 0x00200802, 0x04200000, 0x00000800,
            0x04000002, 0x04000800, 0x00000800, 0x00200002
        };
        private static readonly uint[] SP8 = {
            0x10001040, 0x00001000, 0x00040000, 0x10041040,
            0x10000000, 0x10001040, 0x00000040, 0x10000000,
            0x00040040, 0x10040000, 0x10041040, 0x00041000,
            0x10041000, 0x00041040, 0x00001000, 0x00000040,
            0x10040000, 0x10000040, 0x10001000, 0x00001040,
            0x00041000, 0x00040040, 0x10040040, 0x10041000,
            0x00001040, 0x00000000, 0x00000000, 0x10040040,
            0x10000040, 0x10001000, 0x00041040, 0x00040000,
            0x00041040, 0x00040000, 0x10041000, 0x00001000,
            0x00000040, 0x10040040, 0x00001000, 0x00041040,
            0x10001000, 0x00000040, 0x10000040, 0x10040000,
            0x10040040, 0x10000000, 0x00040000, 0x10001040,
            0x00000000, 0x10041040, 0x00040040, 0x10000040,
            0x10040000, 0x10001000, 0x10001040, 0x00000000,
            0x10041040, 0x00041000, 0x00041000, 0x00001040,
            0x00001040, 0x00040040, 0x10000000, 0x10041000
        };
        private static readonly byte[] pc1 =
        {
            56, 48, 40, 32, 24, 16,  8,  0, 57, 49, 41, 33, 25, 17,
             9,  1, 58, 50, 42, 34, 26, 18, 10,  2, 59, 51, 43, 35,
            62, 54, 46, 38, 30, 22, 14,  6, 61, 53, 45, 37, 29, 21,
            13,  5, 60, 52, 44, 36, 28, 20, 12,  4, 27, 19, 11,  3
        };
        private static readonly byte[] pc2 =
        {
            13, 16, 10, 23,  0,  4,  2, 27, 14,  5, 20,  9,
            22, 18, 11,  3, 25,  7, 15,  6, 26, 19, 12,  1,
            40, 51, 30, 36, 46, 54, 29, 39, 50, 44, 32, 47,
            43, 48, 38, 55, 33, 52, 45, 41, 49, 35, 28, 31
        };
        private static readonly byte[] totrot =
        {
            1, 2, 4, 6, 8, 10, 12, 14, 15, 17, 19, 21, 23, 25, 27, 28
        };
	    ///////////////////////////////////////////////////////////////////////////
	    // Создать расписание ключей
	    ///////////////////////////////////////////////////////////////////////////
        private static uint[] GetKeys(byte[] key, bool encrypting) 
        {
            bool[] pc1m = new bool[56]; 
            bool[] pcr  = new bool[56];

            for (int j = 0; j < pc1m.Length; j++)
            {
                pc1m[j] = ((key[pc1[j] >> 3] & (0x80 >> (pc1[j] & 07))) != 0);
            }
            uint[] newKey = new uint[32];

            for (int i = 0; i < 16; i++)
            {
                int m = (encrypting) ? (i << 1) : (15 - i) << 1; 
            
                newKey[m] = newKey[m + 1] = 0;
                for (int j = 0; j < 28; j++)
                {
                    int l = j + totrot[i];
                    pcr[j] = (l < 28) ? pc1m[l] : pc1m[l - 28];
                }
                for (int j = 28; j < 56; j++)
                {
                    int l = j + totrot[i];
                    pcr[j] = (l < 56) ? pc1m[l] : pc1m[l - 28]; 
                }
                for (int j = 0; j < 24; j++)
                {
                    if (pcr[pc2[j     ]]) newKey[m    ] |= (uint)(0x800000 >> j);
                    if (pcr[pc2[j + 24]]) newKey[m + 1] |= (uint)(0x800000 >> j);
                }
            }
            for (int i = 0; i < 32; i += 2)
            {
                uint i1 = newKey[i]; uint i2 = newKey[i + 1];

                newKey[i]     = ((i1 & 0x00fc0000) <<  6) | ((i1 & 0x00000fc0) << 10) | 
                                ((i2 & 0x00fc0000) >> 10) | ((i2 & 0x00000fc0) >>  6) ;
                newKey[i + 1] = ((i1 & 0x0003f000) << 12) | ((i1 & 0x0000003f) << 16) | 
                                ((i2 & 0x0003f000) >>  4) | ((i2 & 0x0000003f)      ) ;
            }
            return newKey;
        }
	    ///////////////////////////////////////////////////////////////////////////
	    // Функция шифрования данных
	    ///////////////////////////////////////////////////////////////////////////
        private static void DesFunc(uint[] wKey, byte[] input, int inOff, byte[] output, int outOff)
        {
            uint left  = Math.Convert.ToUInt32(input, inOff + 0, Endian); 
            uint right = Math.Convert.ToUInt32(input, inOff + 4, Endian); uint work;

            work   = ((left >> 4) ^ right) & 0x0f0f0f0f;
            right ^= work;
            left  ^= (work << 4);
            work   = ((left >> 16) ^ right) & 0x0000ffff;
            right ^= work;
            left  ^= (work << 16);
            work   = ((right >> 2) ^ left) & 0x33333333;
            left  ^= work;
            right ^= (work << 2);
            work   = ((right >> 8) ^ left) & 0x00ff00ff;
            left  ^= work;
            right ^= (work << 8);
            right  = ((right << 1) | ((right >> 31) & 1)) & 0xffffffff;
            work   = (left ^ right) & 0xaaaaaaaa;
            left  ^= work;
            right ^= work;
            left   = ((left << 1) | ((left >> 31) & 1)) & 0xffffffff;

            for (int round = 0; round < 8; round++)
            {
                uint     fval;

                work  = (right << 28) | (right >> 4);
                work ^= wKey[round * 4 + 0];
                fval  = SP7[ work         & 0x3f];
                fval |= SP5[(work >>  8) & 0x3f];
                fval |= SP3[(work >> 16) & 0x3f];
                fval |= SP1[(work >> 24) & 0x3f];
                work  = right ^ wKey[round * 4 + 1];
                fval |= SP8[ work         & 0x3f];
                fval |= SP6[(work >>  8) & 0x3f];
                fval |= SP4[(work >> 16) & 0x3f];
                fval |= SP2[(work >> 24) & 0x3f];
                left ^= fval;
                work  = (left << 28) | (left >> 4);
                work ^= wKey[round * 4 + 2];
                fval  = SP7[ work         & 0x3f];
                fval |= SP5[(work >>  8) & 0x3f];
                fval |= SP3[(work >> 16) & 0x3f];
                fval |= SP1[(work >> 24) & 0x3f];
                work  = left ^ wKey[round * 4 + 3];
                fval |= SP8[ work         & 0x3f];
                fval |= SP6[(work >>  8) & 0x3f];
                fval |= SP4[(work >> 16) & 0x3f];
                fval |= SP2[(work >> 24) & 0x3f];
                right ^= fval;
            }

            right  = (right << 31) | (right >> 1);
            work   = (left ^ right) & 0xaaaaaaaa;
            left  ^= work;
            right ^= work;
            left   = (left << 31) | (left >> 1);
            work   = ((left >> 8) ^ right) & 0x00ff00ff;
            right ^= work;
            left  ^= (work << 8);
            work   = ((left >> 2) ^ right) & 0x33333333;
            right ^= work;
            left  ^= (work << 2);
            work   = ((right >> 16) ^ left) & 0x0000ffff;
            left  ^= work;
            right ^= (work << 16);
            work   = ((right >> 4) ^ left) & 0x0f0f0f0f;
            left  ^= work;
            right ^= (work << 4);

            Math.Convert.FromUInt32(right, Endian, output, outOff + 0);
            Math.Convert.FromUInt32(left , Endian, output, outOff + 4);
        }
        ////////////////////////////////////////////////////////////////////////////
        // Тесты известного ответа
        ////////////////////////////////////////////////////////////////////////////
        public static void Test(CAPI.Cipher engine)
        {
            CAPI.Cipher.KnownTest(engine, PaddingMode.None, new byte[] {
                (byte)0x7c, (byte)0xa1, (byte)0x10, (byte)0x45, 
                (byte)0x4a, (byte)0x1a, (byte)0x6e, (byte)0x57, 
            }, new byte[] {
                (byte)0x01, (byte)0xa1, (byte)0xd6, (byte)0xd0, 
                (byte)0x39, (byte)0x77, (byte)0x67, (byte)0x42, 
            }, new byte[] {
                (byte)0x69, (byte)0x0f, (byte)0x5b, (byte)0x0d, 
                (byte)0x9a, (byte)0x26, (byte)0x93, (byte)0x9b, 
            }); 
            CAPI.Cipher.KnownTest(engine, PaddingMode.None, new byte[] {
                (byte)0x01, (byte)0x31, (byte)0xd9, (byte)0x61, 
                (byte)0x9d, (byte)0xc1, (byte)0x37, (byte)0x6e, 
            }, new byte[] {
                (byte)0x5c, (byte)0xd5, (byte)0x4c, (byte)0xa8, 
                (byte)0x3d, (byte)0xef, (byte)0x57, (byte)0xda, 
            }, new byte[] {
                (byte)0x7a, (byte)0x38, (byte)0x9d, (byte)0x10, 
                (byte)0x35, (byte)0x4b, (byte)0xd2, (byte)0x71, 
            }); 
            CAPI.Cipher.KnownTest(engine, PaddingMode.None, new byte[] {
                (byte)0x07, (byte)0xa1, (byte)0x13, (byte)0x3e, 
                (byte)0x4a, (byte)0x0b, (byte)0x26, (byte)0x86, 
            }, new byte[] {
                (byte)0x02, (byte)0x48, (byte)0xd4, (byte)0x38, 
                (byte)0x06, (byte)0xf6, (byte)0x71, (byte)0x72, 
            }, new byte[] {
                (byte)0x86, (byte)0x8e, (byte)0xbb, (byte)0x51, 
                (byte)0xca, (byte)0xb4, (byte)0x59, (byte)0x9a, 
            }); 
            CAPI.Cipher.KnownTest(engine, PaddingMode.None, new byte[] {
                (byte)0x38, (byte)0x49, (byte)0x67, (byte)0x4c, 
                (byte)0x26, (byte)0x02, (byte)0x31, (byte)0x9e, 
            }, new byte[] {
                (byte)0x51, (byte)0x45, (byte)0x4b, (byte)0x58, 
                (byte)0x2d, (byte)0xdf, (byte)0x44, (byte)0x0a, 
            }, new byte[] {
                (byte)0x71, (byte)0x78, (byte)0x87, (byte)0x6e, 
                (byte)0x01, (byte)0xf1, (byte)0x9b, (byte)0x2a, 
            }); 
            CAPI.Cipher.KnownTest(engine, PaddingMode.None, new byte[] {
                (byte)0x04, (byte)0xb9, (byte)0x15, (byte)0xba, 
                (byte)0x43, (byte)0xfe, (byte)0xb5, (byte)0xb6, 
            }, new byte[] {
                (byte)0x42, (byte)0xfd, (byte)0x44, (byte)0x30, 
                (byte)0x59, (byte)0x57, (byte)0x7f, (byte)0xa2, 
            }, new byte[] {
                (byte)0xaf, (byte)0x37, (byte)0xfb, (byte)0x42, 
                (byte)0x1f, (byte)0x8c, (byte)0x40, (byte)0x95, 
            }); 
            CAPI.Cipher.KnownTest(engine, PaddingMode.None, new byte[] {
                (byte)0x01, (byte)0x13, (byte)0xb9, (byte)0x70, 
                (byte)0xfd, (byte)0x34, (byte)0xf2, (byte)0xce, 
            }, new byte[] {
                (byte)0x05, (byte)0x9b, (byte)0x5e, (byte)0x08, 
                (byte)0x51, (byte)0xcf, (byte)0x14, (byte)0x3a, 
            }, new byte[] {
                (byte)0x86, (byte)0xa5, (byte)0x60, (byte)0xf1, 
                (byte)0x0e, (byte)0xc6, (byte)0xd8, (byte)0x5b, 
            }); 
            CAPI.Cipher.KnownTest(engine, PaddingMode.None, new byte[] {
                (byte)0x01, (byte)0x70, (byte)0xf1, (byte)0x75, 
                (byte)0x46, (byte)0x8f, (byte)0xb5, (byte)0xe6, 
            }, new byte[] {
                (byte)0x07, (byte)0x56, (byte)0xd8, (byte)0xe0, 
                (byte)0x77, (byte)0x47, (byte)0x61, (byte)0xd2, 
            }, new byte[] {
                (byte)0x0c, (byte)0xd3, (byte)0xda, (byte)0x02, 
                (byte)0x00, (byte)0x21, (byte)0xdc, (byte)0x09, 
            }); 
            CAPI.Cipher.KnownTest(engine, PaddingMode.None, new byte[] {
                (byte)0x43, (byte)0x29, (byte)0x7f, (byte)0xad, 
                (byte)0x38, (byte)0xe3, (byte)0x73, (byte)0xfe, 
            }, new byte[] {
                (byte)0x76, (byte)0x25, (byte)0x14, (byte)0xb8, 
                (byte)0x29, (byte)0xbf, (byte)0x48, (byte)0x6a, 
            }, new byte[] {
                (byte)0xea, (byte)0x67, (byte)0x6b, (byte)0x2c, 
                (byte)0xb7, (byte)0xdb, (byte)0x2b, (byte)0x7a, 
            }); 
            CAPI.Cipher.KnownTest(engine, PaddingMode.None, new byte[] {
                (byte)0x07, (byte)0xa7, (byte)0x13, (byte)0x70, 
                (byte)0x45, (byte)0xda, (byte)0x2a, (byte)0x16, 
            }, new byte[] {
                (byte)0x3b, (byte)0xdd, (byte)0x11, (byte)0x90, 
                (byte)0x49, (byte)0x37, (byte)0x28, (byte)0x02, 
            }, new byte[] {
                (byte)0xdf, (byte)0xd6, (byte)0x4a, (byte)0x81, 
                (byte)0x5c, (byte)0xaf, (byte)0x1a, (byte)0x0f, 
            }); 
            CAPI.Cipher.KnownTest(engine, PaddingMode.None, new byte[] {
                (byte)0x04, (byte)0x68, (byte)0x91, (byte)0x04, 
                (byte)0xc2, (byte)0xfd, (byte)0x3b, (byte)0x2f, 
            }, new byte[] {
                (byte)0x26, (byte)0x95, (byte)0x5f, (byte)0x68, 
                (byte)0x35, (byte)0xaf, (byte)0x60, (byte)0x9a, 
            }, new byte[] {
                (byte)0x5c, (byte)0x51, (byte)0x3c, (byte)0x9c, 
                (byte)0x48, (byte)0x86, (byte)0xc0, (byte)0x88, 
            }); 
            CAPI.Cipher.KnownTest(engine, PaddingMode.None, new byte[] {
                (byte)0x37, (byte)0xd0, (byte)0x6b, (byte)0xb5, 
                (byte)0x16, (byte)0xcb, (byte)0x75, (byte)0x46, 
            }, new byte[] {
                (byte)0x16, (byte)0x4d, (byte)0x5e, (byte)0x40, 
                (byte)0x4f, (byte)0x27, (byte)0x52, (byte)0x32, 
            }, new byte[] {
                (byte)0x0a, (byte)0x2a, (byte)0xee, (byte)0xae, 
                (byte)0x3f, (byte)0xf4, (byte)0xab, (byte)0x77, 
            }); 
            CAPI.Cipher.KnownTest(engine, PaddingMode.None, new byte[] {
                (byte)0x1f, (byte)0x08, (byte)0x26, (byte)0x0d, 
                (byte)0x1a, (byte)0xc2, (byte)0x46, (byte)0x5e, 
            }, new byte[] {
                (byte)0x6b, (byte)0x05, (byte)0x6e, (byte)0x18, 
                (byte)0x75, (byte)0x9f, (byte)0x5c, (byte)0xca, 
            }, new byte[] {
                (byte)0xef, (byte)0x1b, (byte)0xf0, (byte)0x3e, 
                (byte)0x5d, (byte)0xfa, (byte)0x57, (byte)0x5a, 
            }); 
            CAPI.Cipher.KnownTest(engine, PaddingMode.None, new byte[] {
                (byte)0x58, (byte)0x40, (byte)0x23, (byte)0x64, 
                (byte)0x1a, (byte)0xba, (byte)0x61, (byte)0x76, 
            }, new byte[] {
                (byte)0x00, (byte)0x4b, (byte)0xd6, (byte)0xef, 
                (byte)0x09, (byte)0x17, (byte)0x60, (byte)0x62, 
            }, new byte[] {
                (byte)0x88, (byte)0xbf, (byte)0x0d, (byte)0xb6, 
                (byte)0xd7, (byte)0x0d, (byte)0xee, (byte)0x56, 
            }); 
            CAPI.Cipher.KnownTest(engine, PaddingMode.None, new byte[] {
                (byte)0x02, (byte)0x58, (byte)0x16, (byte)0x16, 
                (byte)0x46, (byte)0x29, (byte)0xb0, (byte)0x07, 
            }, new byte[] {
                (byte)0x48, (byte)0x0d, (byte)0x39, (byte)0x00, 
                (byte)0x6e, (byte)0xe7, (byte)0x62, (byte)0xf2, 
            }, new byte[] {
                (byte)0xa1, (byte)0xf9, (byte)0x91, (byte)0x55, 
                (byte)0x41, (byte)0x02, (byte)0x0b, (byte)0x56, 
            }); 
            CAPI.Cipher.KnownTest(engine, PaddingMode.None, new byte[] {
                (byte)0x49, (byte)0x79, (byte)0x3e, (byte)0xbc, 
                (byte)0x79, (byte)0xb3, (byte)0x25, (byte)0x8f, 
            }, new byte[] {
                (byte)0x43, (byte)0x75, (byte)0x40, (byte)0xc8, 
                (byte)0x69, (byte)0x8f, (byte)0x3c, (byte)0xfa, 
            }, new byte[] {
                (byte)0x6f, (byte)0xbf, (byte)0x1c, (byte)0xaf, 
                (byte)0xcf, (byte)0xfd, (byte)0x05, (byte)0x56, 
            }); 
            CAPI.Cipher.KnownTest(engine, PaddingMode.None, new byte[] {
                (byte)0x4f, (byte)0xb0, (byte)0x5e, (byte)0x15, 
                (byte)0x15, (byte)0xab, (byte)0x73, (byte)0xa7, 
            }, new byte[] {
                (byte)0x07, (byte)0x2d, (byte)0x43, (byte)0xa0, 
                (byte)0x77, (byte)0x07, (byte)0x52, (byte)0x92, 
            }, new byte[] {
                (byte)0x2f, (byte)0x22, (byte)0xe4, (byte)0x9b, 
                (byte)0xab, (byte)0x7c, (byte)0xa1, (byte)0xac, 
            }); 
            CAPI.Cipher.KnownTest(engine, PaddingMode.None, new byte[] {
                (byte)0x49, (byte)0xe9, (byte)0x5d, (byte)0x6d, 
                (byte)0x4c, (byte)0xa2, (byte)0x29, (byte)0xbf, 
            }, new byte[] {
                (byte)0x02, (byte)0xfe, (byte)0x55, (byte)0x77, 
                (byte)0x81, (byte)0x17, (byte)0xf1, (byte)0x2a, 
            }, new byte[] {
                (byte)0x5a, (byte)0x6b, (byte)0x61, (byte)0x2c, 
                (byte)0xc2, (byte)0x6c, (byte)0xce, (byte)0x4a, 
            }); 
            CAPI.Cipher.KnownTest(engine, PaddingMode.None, new byte[] {
                (byte)0x01, (byte)0x83, (byte)0x10, (byte)0xdc, 
                (byte)0x40, (byte)0x9b, (byte)0x26, (byte)0xd6, 
            }, new byte[] {
                (byte)0x1d, (byte)0x9d, (byte)0x5c, (byte)0x50, 
                (byte)0x18, (byte)0xf7, (byte)0x28, (byte)0xc2, 
            }, new byte[] {
                (byte)0x5f, (byte)0x4c, (byte)0x03, (byte)0x8e, 
                (byte)0xd1, (byte)0x2b, (byte)0x2e, (byte)0x41, 
            }); 
            CAPI.Cipher.KnownTest(engine, PaddingMode.None, new byte[] {
                (byte)0x1c, (byte)0x58, (byte)0x7f, (byte)0x1c, 
                (byte)0x13, (byte)0x92, (byte)0x4f, (byte)0xef, 
            }, new byte[] {
                (byte)0x30, (byte)0x55, (byte)0x32, (byte)0x28, 
                (byte)0x6d, (byte)0x6f, (byte)0x29, (byte)0x5a, 
            }, new byte[] {
                (byte)0x63, (byte)0xfa, (byte)0xc0, (byte)0xd0, 
                (byte)0x34, (byte)0xd9, (byte)0xf7, (byte)0x93, 
            }); 
        }
        ////////////////////////////////////////////////////////////////////////////
        // SMIME
        ////////////////////////////////////////////////////////////////////////////
        public static void TestSMIME(IBlockCipher des)
        {
            // указать синхропосылку
            byte[] iv = new byte[] { 
                (byte)0xEF, (byte)0xE5, (byte)0x98, (byte)0xEF, 
                (byte)0x21, (byte)0xB3, (byte)0x3D, (byte)0x6D
            }; 
            // создать алгоритм
            using (KeyWrap algorithm = new CAPI.ANSI.Wrap.SMIME(des, 8, iv))
            {
                // создать генератор случайных данных
                using (IRand rand = new CAPI.Rnd.Fixed(new byte[] {
                    (byte)0xC4, (byte)0x36, (byte)0xF5, (byte)0x41 
                })){
                    // выполнить тест
                    KeyWrap.KnownTest(rand, algorithm, new byte[] {
                        (byte)0xD1, (byte)0xDA, (byte)0xA7, (byte)0x86, 
                        (byte)0x15, (byte)0xF2, (byte)0x87, (byte)0xE6 
                    }, new byte[] {
                        (byte)0x8C, (byte)0x62, (byte)0x7C, (byte)0x89, 
                        (byte)0x73, (byte)0x23, (byte)0xA2, (byte)0xF8 
                    }, new byte[] {
                        (byte)0xB8, (byte)0x1B, (byte)0x25, (byte)0x65, 
                        (byte)0xEE, (byte)0x37, (byte)0x3C, (byte)0xA6, 
                        (byte)0xDE, (byte)0xDC, (byte)0xA2, (byte)0x6A, 
                        (byte)0x17, (byte)0x8B, (byte)0x0C, (byte)0x10
                    }); 
                }
            }
        }
    }
}