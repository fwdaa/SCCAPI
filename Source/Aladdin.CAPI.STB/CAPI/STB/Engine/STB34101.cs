using System;

namespace Aladdin.CAPI.STB.Engine
{
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм шифрования BELT
    ///////////////////////////////////////////////////////////////////////////
    public class STB34101 : CAPI.Cipher
    {
        // способ кодирования чисел
        private const Math.Endian Endian = Math.Endian.LittleEndian; 

        // конструктор
        public STB34101(int[] keySizes) { this.keySizes = keySizes; } private int[] keySizes; 
        
        // тип ключа
        public override SecretKeyFactory KeyFactory { get { return Keys.STB34101.Instance; }}
		// размер ключей
		public override int[] KeySizes { get { return keySizes; }}
        // размер блока
		public override int BlockSize { get { return 16;	}}

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
            if (!CAPI.KeySizes.Contains(keySizes, value.Length))
            {
			    // при ошибке выбросить исключение
			    throw new InvalidKeyException();
            }
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
            if (!CAPI.KeySizes.Contains(keySizes, value.Length))
            {
			    // при ошибке выбросить исключение
			    throw new InvalidKeyException();
            }
		    // вернуть алгоритм расшифрования блока данных
		    return new Decryption(key);
		}
	    ///////////////////////////////////////////////////////////////////////////
	    // Алгоритм шифрования блока
	    ///////////////////////////////////////////////////////////////////////////
	    public abstract class BlockTransform : CAPI.BlockTransform
	    {
		    // расписание ключей
            private uint[] keys = new uint[8]; 
        
		    // конструктор
            protected BlockTransform(ISecretKey key) : base(16)
            { 
			    // проверить тип ключа
			    byte[] value = key.Value; if (value == null)
			    {
				    // при ошибке выбросить исключение
				    throw new InvalidKeyException();
			    }
                // проверить корректность размера ключа
                if (value.Length != 16 && value.Length != 24 && value.Length != 32)
                {
				    // при ошибке выбросить исключение
				    throw new InvalidKeyException();
                }
                // скопировать ключ
                keys[0] = Math.Convert.ToUInt32(value,  0, Endian); 
                keys[1] = Math.Convert.ToUInt32(value,  4, Endian); 
                keys[2] = Math.Convert.ToUInt32(value,  8, Endian); 
                keys[3] = Math.Convert.ToUInt32(value, 12, Endian);

                // в зависимости от размера ключа
                if (value.Length == 16)
                {
                    // расширить ключ
                    keys[4] = keys[0]; keys[5] = keys[1]; 
                    keys[6] = keys[2]; keys[7] = keys[3];
                }
                // в зависимости от размера ключа
                else if (value.Length == 24)
                {
                    // скопировать ключ
                    keys[4] = Math.Convert.ToUInt32(value, 16, Endian);
                    keys[5] = Math.Convert.ToUInt32(value, 20, Endian);
                
                    // расширить ключ
                    keys[6] = keys[0] ^ keys[1] ^ keys[2];
                    keys[7] = keys[3] ^ keys[4] ^ keys[5]; 
                }
                // в зависимости от размера ключа
                else if (value.Length == 32)
                {
                    // скопировать ключ
                    keys[4] = Math.Convert.ToUInt32(value, 16, Endian);
                    keys[5] = Math.Convert.ToUInt32(value, 20, Endian);
                    keys[6] = Math.Convert.ToUInt32(value, 24, Endian);
                    keys[7] = Math.Convert.ToUInt32(value, 28, Endian);
                }
            } 
		    // преобразование одного раунда
		    protected abstract void Round(uint[] key, int n, uint i, uint[] abcd); 

		    // перестановка
		    protected abstract void Perm(uint[] abcd); 

		    // преобразовать блок
		    protected override void Update(byte[] data, int dataOff, byte[] buf, int bufOff)
		    {
                uint[] abcd = new uint[4]; 
            
			    // извлечь данные для преобразования
			    abcd[0] = Math.Convert.ToUInt32(data, dataOff +  0, Endian); 
			    abcd[1] = Math.Convert.ToUInt32(data, dataOff +  4, Endian); 
			    abcd[2] = Math.Convert.ToUInt32(data, dataOff +  8, Endian); 
			    abcd[3] = Math.Convert.ToUInt32(data, dataOff + 12, Endian); 
                    
			    // выполнить 8 раундов
			    Round(keys, 0, 1, abcd); Perm(abcd); Round(keys, 7, 2, abcd); Perm(abcd);
			    Round(keys, 6, 3, abcd); Perm(abcd); Round(keys, 5, 4, abcd); Perm(abcd);
			    Round(keys, 4, 5, abcd); Perm(abcd); Round(keys, 3, 6, abcd); Perm(abcd);
			    Round(keys, 2, 7, abcd); Perm(abcd); Round(keys, 1, 8, abcd); Perm(abcd);

			    // выполнить перестановку
			    Perm(abcd); 

			    // вернуть результат
                Math.Convert.FromUInt32(abcd[0], Endian, buf, bufOff +  0);
                Math.Convert.FromUInt32(abcd[1], Endian, buf, bufOff +  4);
                Math.Convert.FromUInt32(abcd[2], Endian, buf, bufOff +  8);
                Math.Convert.FromUInt32(abcd[3], Endian, buf, bufOff + 12);
 		    }
        }
	    ///////////////////////////////////////////////////////////////////////////
	    // Алгоритм зашифрования блока
	    ///////////////////////////////////////////////////////////////////////////
	    public class Encryption : BlockTransform
	    {
		    // конструктор
		    public Encryption(ISecretKey key) : base(key) {}

		    // преобразование одного раунда
		    protected override void Round(uint[] key, int n, uint i, uint[] abcd)
		    {
			    uint a = abcd[0]; uint b = abcd[1]; uint c = abcd[2]; uint d = abcd[3]; uint e;   

			    // преобразование одного раунда
			    e = a		+ key[n]; b ^= G5 (e);		n = (n + 1) & 7;						
			    e = d		+ key[n]; c ^= G21(e);		n = (n + 1) & 7;						
			    e = b		+ key[n]; a -= G13(e);		n = (n + 1) & 7;						
			    e = b + c	+ key[n]; e  = G21(e) ^ i;	n = (n + 1) & 7; b += e; c -= e;		
			    e = c		+ key[n]; d += G13(e);		n = (n + 1) & 7;						
			    e = a		+ key[n]; b ^= G21(e);		n = (n + 1) & 7;						
			    e = d		+ key[n]; c ^= G5 (e);		n = (n + 1) & 7;
            
                abcd[0] = a; abcd[1] = b; abcd[2] = c; abcd[3] = d;
		    }
		    // выполнить перестановку
		    protected override void Perm(uint[] abcd)
		    {
			    // выполнить перестановку
			    uint e = abcd[2]; abcd[2] = abcd[0]; abcd[0] = abcd[1]; abcd[1] = abcd[3]; abcd[3] = e;
		    }
	    }
	    ///////////////////////////////////////////////////////////////////////////
	    // Алгоритм расшифрования блока
	    ///////////////////////////////////////////////////////////////////////////
	    public class Decryption : BlockTransform
	    {
		    // конструктор
		    public Decryption(ISecretKey key) : base(key) {}

		    // преобразование одного раунда
		    protected override void Round(uint[] key, int n, uint i, uint[] abcd)
		    {
			    uint a = abcd[0]; uint b = abcd[1]; uint c = abcd[2]; uint d = abcd[3]; uint e; i = 9 - i; 

			    // преобразование одного раунда
			    e = a		+ key[7 - n]; b ^= G5 (e);		n = (n + 1) & 7;						
			    e = d		+ key[7 - n]; c ^= G21(e);		n = (n + 1) & 7;						
			    e = b		+ key[7 - n]; a -= G13(e);		n = (n + 1) & 7;						
			    e = b + c	+ key[7 - n]; e  = G21(e) ^ i;	n = (n + 1) & 7; b += e; c -= e;
			    e = c		+ key[7 - n]; d += G13(e);		n = (n + 1) & 7;						
			    e = a		+ key[7 - n]; b ^= G21(e);		n = (n + 1) & 7;						
			    e = d		+ key[7 - n]; c ^= G5 (e);		n = (n + 1) & 7;						

                abcd[0] = a; abcd[1] = b; abcd[2] = c; abcd[3] = d;
            }
		    // выполнить перестановку
		    protected override void Perm(uint[] abcd)
		    {
			    // выполнить перестановку
			    uint e = abcd[1]; abcd[1] = abcd[0]; abcd[0] = abcd[2]; abcd[2] = abcd[3]; abcd[3] = e;
		    }
	    }
	    ///////////////////////////////////////////////////////////////////////////
	    // Вспомогательные таблицы и преобразования
	    ///////////////////////////////////////////////////////////////////////////
        public static readonly byte[] H = {
		    (byte)0xB1, (byte)0x94, (byte)0xBA, (byte)0xC8, 
		    (byte)0x0A, (byte)0x08, (byte)0xF5, (byte)0x3B, 
		    (byte)0x36, (byte)0x6D, (byte)0x00, (byte)0x8E, 
		    (byte)0x58, (byte)0x4A, (byte)0x5D, (byte)0xE4,
		    (byte)0x85, (byte)0x04, (byte)0xFA, (byte)0x9D, 
		    (byte)0x1B, (byte)0xB6, (byte)0xC7, (byte)0xAC, 
		    (byte)0x25, (byte)0x2E, (byte)0x72, (byte)0xC2, 
		    (byte)0x02, (byte)0xFD, (byte)0xCE, (byte)0x0D,
		    (byte)0x5B, (byte)0xE3, (byte)0xD6, (byte)0x12, 
		    (byte)0x17, (byte)0xB9, (byte)0x61, (byte)0x81, 
		    (byte)0xFE, (byte)0x67, (byte)0x86, (byte)0xAD, 
		    (byte)0x71, (byte)0x6B, (byte)0x89, (byte)0x0B,
		    (byte)0x5C, (byte)0xB0, (byte)0xC0, (byte)0xFF, 
		    (byte)0x33, (byte)0xC3, (byte)0x56, (byte)0xB8, 
		    (byte)0x35, (byte)0xC4, (byte)0x05, (byte)0xAE, 
		    (byte)0xD8, (byte)0xE0, (byte)0x7F, (byte)0x99,
		    (byte)0xE1, (byte)0x2B, (byte)0xDC, (byte)0x1A, 
		    (byte)0xE2, (byte)0x82, (byte)0x57, (byte)0xEC, 
		    (byte)0x70, (byte)0x3F, (byte)0xCC, (byte)0xF0, 
		    (byte)0x95, (byte)0xEE, (byte)0x8D, (byte)0xF1,
		    (byte)0xC1, (byte)0xAB, (byte)0x76, (byte)0x38, 
		    (byte)0x9F, (byte)0xE6, (byte)0x78, (byte)0xCA, 
		    (byte)0xF7, (byte)0xC6, (byte)0xF8, (byte)0x60, 
		    (byte)0xD5, (byte)0xBB, (byte)0x9C, (byte)0x4F,
		    (byte)0xF3, (byte)0x3C, (byte)0x65, (byte)0x7B, 
		    (byte)0x63, (byte)0x7C, (byte)0x30, (byte)0x6A, 
		    (byte)0xDD, (byte)0x4E, (byte)0xA7, (byte)0x79, 
		    (byte)0x9E, (byte)0xB2, (byte)0x3D, (byte)0x31,
		    (byte)0x3E, (byte)0x98, (byte)0xB5, (byte)0x6E, 
		    (byte)0x27, (byte)0xD3, (byte)0xBC, (byte)0xCF, 
		    (byte)0x59, (byte)0x1E, (byte)0x18, (byte)0x1F, 
		    (byte)0x4C, (byte)0x5A, (byte)0xB7, (byte)0x93,
		    (byte)0xE9, (byte)0xDE, (byte)0xE7, (byte)0x2C, 
		    (byte)0x8F, (byte)0x0C, (byte)0x0F, (byte)0xA6, 
		    (byte)0x2D, (byte)0xDB, (byte)0x49, (byte)0xF4, 
		    (byte)0x6F, (byte)0x73, (byte)0x96, (byte)0x47,
		    (byte)0x06, (byte)0x07, (byte)0x53, (byte)0x16, 
		    (byte)0xED, (byte)0x24, (byte)0x7A, (byte)0x37, 
		    (byte)0x39, (byte)0xCB, (byte)0xA3, (byte)0x83, 
		    (byte)0x03, (byte)0xA9, (byte)0x8B, (byte)0xF6,
		    (byte)0x92, (byte)0xBD, (byte)0x9B, (byte)0x1C, 
		    (byte)0xE5, (byte)0xD1, (byte)0x41, (byte)0x01, 
		    (byte)0x54, (byte)0x45, (byte)0xFB, (byte)0xC9, 
		    (byte)0x5E, (byte)0x4D, (byte)0x0E, (byte)0xF2,
		    (byte)0x68, (byte)0x20, (byte)0x80, (byte)0xAA, 
		    (byte)0x22, (byte)0x7D, (byte)0x64, (byte)0x2F, 
		    (byte)0x26, (byte)0x87, (byte)0xF9, (byte)0x34, 
		    (byte)0x90, (byte)0x40, (byte)0x55, (byte)0x11,
		    (byte)0xBE, (byte)0x32, (byte)0x97, (byte)0x13, 
		    (byte)0x43, (byte)0xFC, (byte)0x9A, (byte)0x48, 
		    (byte)0xA0, (byte)0x2A, (byte)0x88, (byte)0x5F, 
		    (byte)0x19, (byte)0x4B, (byte)0x09, (byte)0xA1,
		    (byte)0x7E, (byte)0xCD, (byte)0xA4, (byte)0xD0, 
		    (byte)0x15, (byte)0x44, (byte)0xAF, (byte)0x8C, 
		    (byte)0xA5, (byte)0x84, (byte)0x50, (byte)0xBF, 
		    (byte)0x66, (byte)0xD2, (byte)0xE8, (byte)0x8A,
		    (byte)0xA2, (byte)0xD7, (byte)0x46, (byte)0x52, 
		    (byte)0x42, (byte)0xA8, (byte)0xDF, (byte)0xB3, 
		    (byte)0x69, (byte)0x74, (byte)0xC5, (byte)0x51, 
		    (byte)0xEB, (byte)0x23, (byte)0x29, (byte)0x21,
		    (byte)0xD4, (byte)0xEF, (byte)0xD9, (byte)0xB4, 
		    (byte)0x3A, (byte)0x62, (byte)0x28, (byte)0x75, 
		    (byte)0x91, (byte)0x14, (byte)0x10, (byte)0xEA, 
		    (byte)0x77, (byte)0x6C, (byte)0xDA, (byte)0x1D
        };
        // расширенная таблица замены BELT
        private static readonly uint[] H1 = new uint[256];
        private static readonly uint[] H2 = new uint[256];
        private static readonly uint[] H3 = new uint[256];
        private static readonly uint[] H4 = new uint[256]; 
        static STB34101()
        {
            for (int i = 0; i < 256; i++)
            {
                H1[i]  = (uint)( H[i] <<  5);
                H2[i]  = (uint)( H[i] << 13);
                H3[i]  = (uint)( H[i] << 21);
                H4[i]  = (uint)((H[i] << 29) | (H[i] >>  3)); 
            }
        }
        private static uint G5(uint t)
        {
            // выполнить преобразование
            return H1[t & 0xFF] ^ H2[(t >> 8) & 0xFF] ^ H3[(t >> 16) & 0xFF] ^ H4[t >> 24];  
        }
        private static uint G13(uint t)
        {
            // выполнить преобразование
            return H2[t & 0xFF] ^ H3[(t >> 8) & 0xFF] ^ H4[(t >> 16) & 0xFF] ^ H1[t >> 24]; 
        }
        private static uint G21(uint t)
        {
            // выполнить преобразование
            return H3[t & 0xFF] ^ H4[(t >> 8) & 0xFF] ^ H1[(t >> 16) & 0xFF] ^ H2[t >> 24]; 
        }
	    ///////////////////////////////////////////////////////////////////////////
	    // Тесты известного ответа
	    ///////////////////////////////////////////////////////////////////////////
        public static void Test(IBlockCipher blockCipher) 
        {
            CipherMode mode = new CipherMode.ECB(); 
        
            // создать режим шифрования
            using (CAPI.Cipher cipher = blockCipher.CreateBlockMode(mode))
            { 
                // выполнить тест
                if (CAPI.KeySizes.Contains(cipher.KeySizes, 32))
                CAPI.Cipher.KnownTest(cipher, PaddingMode.Any, new byte[] {
                    (byte)0xE9, (byte)0xDE, (byte)0xE7, (byte)0x2C, 
                    (byte)0x8F, (byte)0x0C, (byte)0x0F, (byte)0xA6, 
                    (byte)0x2D, (byte)0xDB, (byte)0x49, (byte)0xF4, 
                    (byte)0x6F, (byte)0x73, (byte)0x96, (byte)0x47, 
                    (byte)0x06, (byte)0x07, (byte)0x53, (byte)0x16, 
                    (byte)0xED, (byte)0x24, (byte)0x7A, (byte)0x37, 
                    (byte)0x39, (byte)0xCB, (byte)0xA3, (byte)0x83, 
                    (byte)0x03, (byte)0xA9, (byte)0x8B, (byte)0xF6		
                }, new byte[] {
                    (byte)0xB1, (byte)0x94, (byte)0xBA, (byte)0xC8, 
                    (byte)0x0A, (byte)0x08, (byte)0xF5, (byte)0x3B, 
                    (byte)0x36, (byte)0x6D, (byte)0x00, (byte)0x8E, 
                    (byte)0x58, (byte)0x4A, (byte)0x5D, (byte)0xE4, 
                    (byte)0x85, (byte)0x04, (byte)0xFA, (byte)0x9D, 
                    (byte)0x1B, (byte)0xB6, (byte)0xC7, (byte)0xAC, 
                    (byte)0x25, (byte)0x2E, (byte)0x72, (byte)0xC2, 
                    (byte)0x02, (byte)0xFD, (byte)0xCE, (byte)0x0D,
                    (byte)0x5B, (byte)0xE3, (byte)0xD6, (byte)0x12, 
                    (byte)0x17, (byte)0xB9, (byte)0x61, (byte)0x81, 
                    (byte)0xFE, (byte)0x67, (byte)0x86, (byte)0xAD, 
                    (byte)0x71, (byte)0x6B, (byte)0x89, (byte)0x0B		
                }, new byte[] {
                    (byte)0x69, (byte)0xCC, (byte)0xA1, (byte)0xC9, 
                    (byte)0x35, (byte)0x57, (byte)0xC9, (byte)0xE3, 
                    (byte)0xD6, (byte)0x6B, (byte)0xC3, (byte)0xE0,
                    (byte)0xFA, (byte)0x88, (byte)0xFA, (byte)0x6E, 
                    (byte)0x5F, (byte)0x23, (byte)0x10, (byte)0x2E, 
                    (byte)0xF1, (byte)0x09, (byte)0x71, (byte)0x07, 
                    (byte)0x75, (byte)0x01, (byte)0x7F, (byte)0x73, 
                    (byte)0x80, (byte)0x6D, (byte)0xA9, (byte)0xDC,
                    (byte)0x46, (byte)0xFB, (byte)0x2E, (byte)0xD2, 
                    (byte)0xCE, (byte)0x77, (byte)0x1F, (byte)0x26, 
                    (byte)0xDC, (byte)0xB5, (byte)0xE5, (byte)0xD1, 
                    (byte)0x56, (byte)0x9F, (byte)0x9A, (byte)0xB0		
                });
                if (CAPI.KeySizes.Contains(cipher.KeySizes, 32))
                CAPI.Cipher.KnownTest(cipher, PaddingMode.Any, new byte[] {
                    (byte)0xE9, (byte)0xDE, (byte)0xE7, (byte)0x2C, 
                    (byte)0x8F, (byte)0x0C, (byte)0x0F, (byte)0xA6, 
                    (byte)0x2D, (byte)0xDB, (byte)0x49, (byte)0xF4, 
                    (byte)0x6F, (byte)0x73, (byte)0x96, (byte)0x47, 
                    (byte)0x06, (byte)0x07, (byte)0x53, (byte)0x16, 
                    (byte)0xED, (byte)0x24, (byte)0x7A, (byte)0x37, 
                    (byte)0x39, (byte)0xCB, (byte)0xA3, (byte)0x83, 
                    (byte)0x03, (byte)0xA9, (byte)0x8B, (byte)0xF6		
                }, new byte[] {
                    (byte)0xB1, (byte)0x94, (byte)0xBA, (byte)0xC8, 
                    (byte)0x0A, (byte)0x08, (byte)0xF5, (byte)0x3B, 
                    (byte)0x36, (byte)0x6D, (byte)0x00, (byte)0x8E, 
                    (byte)0x58, (byte)0x4A, (byte)0x5D, (byte)0xE4, 
                    (byte)0x85, (byte)0x04, (byte)0xFA, (byte)0x9D, 
                    (byte)0x1B, (byte)0xB6, (byte)0xC7, (byte)0xAC, 
                    (byte)0x25, (byte)0x2E, (byte)0x72, (byte)0xC2, 
                    (byte)0x02, (byte)0xFD, (byte)0xCE, (byte)0x0D,
                    (byte)0x5B, (byte)0xE3, (byte)0xD6, (byte)0x12, 
                    (byte)0x17, (byte)0xB9, (byte)0x61, (byte)0x81, 
                    (byte)0xFE, (byte)0x67, (byte)0x86, (byte)0xAD, 
                    (byte)0x71, (byte)0x6B, (byte)0x89		
                }, new byte[] {
                    (byte)0x69, (byte)0xCC, (byte)0xA1, (byte)0xC9, 
                    (byte)0x35, (byte)0x57, (byte)0xC9, (byte)0xE3, 
                    (byte)0xD6, (byte)0x6B, (byte)0xC3, (byte)0xE0, 
                    (byte)0xFA, (byte)0x88, (byte)0xFA, (byte)0x6E, 
                    (byte)0x36, (byte)0xF0, (byte)0x0C, (byte)0xFE, 
                    (byte)0xD6, (byte)0xD1, (byte)0xCA, (byte)0x14, 
                    (byte)0x98, (byte)0xC1, (byte)0x27, (byte)0x98, 
                    (byte)0xF4, (byte)0xBE, (byte)0xB2, (byte)0x07,
                    (byte)0x5F, (byte)0x23, (byte)0x10, (byte)0x2E, 
                    (byte)0xF1, (byte)0x09, (byte)0x71, (byte)0x07, 
                    (byte)0x75, (byte)0x01, (byte)0x7F, (byte)0x73, 
                    (byte)0x80, (byte)0x6D, (byte)0xA9
                }); 
                if (CAPI.KeySizes.Contains(cipher.KeySizes, 32))
                CAPI.Cipher.KnownTest(cipher, PaddingMode.Any, new byte[] {
                    (byte)0x92, (byte)0xBD, (byte)0x9B, (byte)0x1C, 
                    (byte)0xE5, (byte)0xD1, (byte)0x41, (byte)0x01, 
                    (byte)0x54, (byte)0x45, (byte)0xFB, (byte)0xC9, 
                    (byte)0x5E, (byte)0x4D, (byte)0x0E, (byte)0xF2, 
                    (byte)0x68, (byte)0x20, (byte)0x80, (byte)0xAA, 
                    (byte)0x22, (byte)0x7D, (byte)0x64, (byte)0x2F, 
                    (byte)0x26, (byte)0x87, (byte)0xF9, (byte)0x34, 
                    (byte)0x90, (byte)0x40, (byte)0x55, (byte)0x11,		
                }, new byte[] {
                    (byte)0x0D, (byte)0xC5, (byte)0x30, (byte)0x06, 
                    (byte)0x00, (byte)0xCA, (byte)0xB8, (byte)0x40, 
                    (byte)0xB3, (byte)0x84, (byte)0x48, (byte)0xE5, 
                    (byte)0xE9, (byte)0x93, (byte)0xF4, (byte)0x21, 
                    (byte)0xE5, (byte)0x5A, (byte)0x23, (byte)0x9F, 
                    (byte)0x2A, (byte)0xB5, (byte)0xC5, (byte)0xD5, 
                    (byte)0xFD, (byte)0xB6, (byte)0xE8, (byte)0x1B, 
                    (byte)0x40, (byte)0x93, (byte)0x8E, (byte)0x2A,
                    (byte)0x54, (byte)0x12, (byte)0x0C, (byte)0xA3, 
                    (byte)0xE6, (byte)0xE1, (byte)0x9C, (byte)0x7A, 
                    (byte)0xD7, (byte)0x50, (byte)0xFC, (byte)0x35, 
                    (byte)0x31, (byte)0xDA, (byte)0xEA, (byte)0xB7,
                }, new byte[] {
                    (byte)0xE1, (byte)0x2B, (byte)0xDC, (byte)0x1A, 
                    (byte)0xE2, (byte)0x82, (byte)0x57, (byte)0xEC, 
                    (byte)0x70, (byte)0x3F, (byte)0xCC, (byte)0xF0, 
                    (byte)0x95, (byte)0xEE, (byte)0x8D, (byte)0xF1, 
                    (byte)0xC1, (byte)0xAB, (byte)0x76, (byte)0x38, 
                    (byte)0x9F, (byte)0xE6, (byte)0x78, (byte)0xCA,
                    (byte)0xF7, (byte)0xC6, (byte)0xF8, (byte)0x60, 
                    (byte)0xD5, (byte)0xBB, (byte)0x9C, (byte)0x4F,
                    (byte)0xF3, (byte)0x3C, (byte)0x65, (byte)0x7B, 
                    (byte)0x63, (byte)0x7C, (byte)0x30, (byte)0x6A, 
                    (byte)0xDD, (byte)0x4E, (byte)0xA7, (byte)0x79, 
                    (byte)0x9E, (byte)0xB2, (byte)0x3D, (byte)0x31
                }); 
                if (CAPI.KeySizes.Contains(cipher.KeySizes, 32))
                CAPI.Cipher.KnownTest(cipher, PaddingMode.Any, new byte[] {
                    (byte)0x92, (byte)0xBD, (byte)0x9B, (byte)0x1C, 
                    (byte)0xE5, (byte)0xD1, (byte)0x41, (byte)0x01, 
                    (byte)0x54, (byte)0x45, (byte)0xFB, (byte)0xC9, 
                    (byte)0x5E, (byte)0x4D, (byte)0x0E, (byte)0xF2, 
                    (byte)0x68, (byte)0x20, (byte)0x80, (byte)0xAA, 
                    (byte)0x22, (byte)0x7D, (byte)0x64, (byte)0x2F, 
                    (byte)0x26, (byte)0x87, (byte)0xF9, (byte)0x34, 
                    (byte)0x90, (byte)0x40, (byte)0x55, (byte)0x11,		
                }, new byte[] {
                    (byte)0x0D, (byte)0xC5, (byte)0x30, (byte)0x06, 
                    (byte)0x00, (byte)0xCA, (byte)0xB8, (byte)0x40, 
                    (byte)0xB3, (byte)0x84, (byte)0x48, (byte)0xE5, 
                    (byte)0xE9, (byte)0x93, (byte)0xF4, (byte)0x21, 
                    (byte)0x57, (byte)0x80, (byte)0xA6, (byte)0xE2, 
                    (byte)0xB6, (byte)0x9E, (byte)0xAF, (byte)0xBB, 
                    (byte)0x25, (byte)0x87, (byte)0x26, (byte)0xD7, 
                    (byte)0xB6, (byte)0x71, (byte)0x85, (byte)0x23,
                    (byte)0xE5, (byte)0x5A, (byte)0x23, (byte)0x9F
                }, new byte[] {
                    (byte)0xE1, (byte)0x2B, (byte)0xDC, (byte)0x1A, 
                    (byte)0xE2, (byte)0x82, (byte)0x57, (byte)0xEC, 
                    (byte)0x70, (byte)0x3F, (byte)0xCC, (byte)0xF0, 
                    (byte)0x95, (byte)0xEE, (byte)0x8D, (byte)0xF1, 
                    (byte)0xC1, (byte)0xAB, (byte)0x76, (byte)0x38, 
                    (byte)0x9F, (byte)0xE6, (byte)0x78, (byte)0xCA, 
                    (byte)0xF7, (byte)0xC6, (byte)0xF8, (byte)0x60, 
                    (byte)0xD5, (byte)0xBB, (byte)0x9C, (byte)0x4F,
                    (byte)0xF3, (byte)0x3C, (byte)0x65, (byte)0x7B
                }); 
            }
            mode = new CipherMode.CBC(new byte[] {
                (byte)0xBE, (byte)0x32, (byte)0x97, (byte)0x13, 
                (byte)0x43, (byte)0xFC, (byte)0x9A, (byte)0x48, 
                (byte)0xA0, (byte)0x2A, (byte)0x88, (byte)0x5F, 
                (byte)0x19, (byte)0x4B, (byte)0x09, (byte)0xA1,
            }); 
            // создать режим шифрования
            using (CAPI.Cipher cipher = blockCipher.CreateBlockMode(mode))
            { 
                if (CAPI.KeySizes.Contains(cipher.KeySizes, 32))
                CAPI.Cipher.KnownTest(cipher, PaddingMode.Any, new byte[] {
                    (byte)0xE9, (byte)0xDE, (byte)0xE7, (byte)0x2C, 
                    (byte)0x8F, (byte)0x0C, (byte)0x0F, (byte)0xA6, 
                    (byte)0x2D, (byte)0xDB, (byte)0x49, (byte)0xF4, 
                    (byte)0x6F, (byte)0x73, (byte)0x96, (byte)0x47, 
                    (byte)0x06, (byte)0x07, (byte)0x53, (byte)0x16, 
                    (byte)0xED, (byte)0x24, (byte)0x7A, (byte)0x37, 
                    (byte)0x39, (byte)0xCB, (byte)0xA3, (byte)0x83, 
                    (byte)0x03, (byte)0xA9, (byte)0x8B, (byte)0xF6		
                }, new byte[] {
                    (byte)0xB1, (byte)0x94, (byte)0xBA, (byte)0xC8, 
                    (byte)0x0A, (byte)0x08, (byte)0xF5, (byte)0x3B, 
                    (byte)0x36, (byte)0x6D, (byte)0x00, (byte)0x8E, 
                    (byte)0x58, (byte)0x4A, (byte)0x5D, (byte)0xE4, 
                    (byte)0x85, (byte)0x04, (byte)0xFA, (byte)0x9D, 
                    (byte)0x1B, (byte)0xB6, (byte)0xC7, (byte)0xAC, 
                    (byte)0x25, (byte)0x2E, (byte)0x72, (byte)0xC2, 
                    (byte)0x02, (byte)0xFD, (byte)0xCE, (byte)0x0D,
                    (byte)0x5B, (byte)0xE3, (byte)0xD6, (byte)0x12, 
                    (byte)0x17, (byte)0xB9, (byte)0x61, (byte)0x81, 
                    (byte)0xFE, (byte)0x67, (byte)0x86, (byte)0xAD, 
                    (byte)0x71, (byte)0x6B, (byte)0x89, (byte)0x0B
                }, new byte[] {
                    (byte)0x10, (byte)0x11, (byte)0x6E, (byte)0xFA, 
                    (byte)0xE6, (byte)0xAD, (byte)0x58, (byte)0xEE, 
                    (byte)0x14, (byte)0x85, (byte)0x2E, (byte)0x11, 
                    (byte)0xDA, (byte)0x1B, (byte)0x8A, (byte)0x74, 
                    (byte)0x5C, (byte)0xF2, (byte)0x48, (byte)0x0E, 
                    (byte)0x8D, (byte)0x03, (byte)0xF1, (byte)0xC1, 
                    (byte)0x94, (byte)0x92, (byte)0xE5, (byte)0x3E, 
                    (byte)0xD3, (byte)0xA7, (byte)0x0F, (byte)0x60,
                    (byte)0x65, (byte)0x7C, (byte)0x1E, (byte)0xE8, 
                    (byte)0xC0, (byte)0xE0, (byte)0xAE, (byte)0x5B, 
                    (byte)0x58, (byte)0x38, (byte)0x8B, (byte)0xF8, 
                    (byte)0xA6, (byte)0x8E, (byte)0x33, (byte)0x09
                }); 
                if (CAPI.KeySizes.Contains(cipher.KeySizes, 32))
                CAPI.Cipher.KnownTest(cipher, PaddingMode.Any, new byte[] {
                    (byte)0xE9, (byte)0xDE, (byte)0xE7, (byte)0x2C, 
                    (byte)0x8F, (byte)0x0C, (byte)0x0F, (byte)0xA6, 
                    (byte)0x2D, (byte)0xDB, (byte)0x49, (byte)0xF4, 
                    (byte)0x6F, (byte)0x73, (byte)0x96, (byte)0x47, 
                    (byte)0x06, (byte)0x07, (byte)0x53, (byte)0x16, 
                    (byte)0xED, (byte)0x24, (byte)0x7A, (byte)0x37, 
                    (byte)0x39, (byte)0xCB, (byte)0xA3, (byte)0x83, 
                    (byte)0x03, (byte)0xA9, (byte)0x8B, (byte)0xF6		
                }, new byte[] {
                    (byte)0xB1, (byte)0x94, (byte)0xBA, (byte)0xC8, 
                    (byte)0x0A, (byte)0x08, (byte)0xF5, (byte)0x3B, 
                    (byte)0x36, (byte)0x6D, (byte)0x00, (byte)0x8E, 
                    (byte)0x58, (byte)0x4A, (byte)0x5D, (byte)0xE4, 
                    (byte)0x85, (byte)0x04, (byte)0xFA, (byte)0x9D, 
                    (byte)0x1B, (byte)0xB6, (byte)0xC7, (byte)0xAC, 
                    (byte)0x25, (byte)0x2E, (byte)0x72, (byte)0xC2, 
                    (byte)0x02, (byte)0xFD, (byte)0xCE, (byte)0x0D,
                    (byte)0x5B, (byte)0xE3, (byte)0xD6, (byte)0x12 
                }, new byte[] {
                    (byte)0x10, (byte)0x11, (byte)0x6E, (byte)0xFA, 
                    (byte)0xE6, (byte)0xAD, (byte)0x58, (byte)0xEE, 
                    (byte)0x14, (byte)0x85, (byte)0x2E, (byte)0x11, 
                    (byte)0xDA, (byte)0x1B, (byte)0x8A, (byte)0x74,
                    (byte)0x6A, (byte)0x9B, (byte)0xBA, (byte)0xDC, 
                    (byte)0xAF, (byte)0x73, (byte)0xF9, (byte)0x68, 
                    (byte)0xF8, (byte)0x75, (byte)0xDE, (byte)0xDC, 
                    (byte)0x0A, (byte)0x44, (byte)0xF6, (byte)0xB1,
                    (byte)0x5C, (byte)0xF2, (byte)0x48, (byte)0x0E
                }); 
            }
            mode = new CipherMode.CBC(new byte[] {
                (byte)0x7E, (byte)0xCD, (byte)0xA4, (byte)0xD0, 
                (byte)0x15, (byte)0x44, (byte)0xAF, (byte)0x8C, 
                (byte)0xA5, (byte)0x84, (byte)0x50, (byte)0xBF, 
                (byte)0x66, (byte)0xD2, (byte)0xE8, (byte)0x8A
            }); 
            // создать режим шифрования
            using (CAPI.Cipher cipher = blockCipher.CreateBlockMode(mode))
            { 
                if (CAPI.KeySizes.Contains(cipher.KeySizes, 32))
                CAPI.Cipher.KnownTest(cipher, PaddingMode.Any, new byte[] {
                    (byte)0x92, (byte)0xBD, (byte)0x9B, (byte)0x1C, 
                    (byte)0xE5, (byte)0xD1, (byte)0x41, (byte)0x01, 
                    (byte)0x54, (byte)0x45, (byte)0xFB, (byte)0xC9, 
                    (byte)0x5E, (byte)0x4D, (byte)0x0E, (byte)0xF2, 
                    (byte)0x68, (byte)0x20, (byte)0x80, (byte)0xAA, 
                    (byte)0x22, (byte)0x7D, (byte)0x64, (byte)0x2F, 
                    (byte)0x26, (byte)0x87, (byte)0xF9, (byte)0x34, 
                    (byte)0x90, (byte)0x40, (byte)0x55, (byte)0x11,		
                }, new byte[] {
                    (byte)0x73, (byte)0x08, (byte)0x94, (byte)0xD6, 
                    (byte)0x15, (byte)0x8E, (byte)0x17, (byte)0xCC, 
                    (byte)0x16, (byte)0x00, (byte)0x18, (byte)0x5A, 
                    (byte)0x8F, (byte)0x41, (byte)0x1C, (byte)0xAB, 
                    (byte)0x04, (byte)0x71, (byte)0xFF, (byte)0x85, 
                    (byte)0xC8, (byte)0x37, (byte)0x92, (byte)0x39, 
                    (byte)0x8D, (byte)0x89, (byte)0x24, (byte)0xEB, 
                    (byte)0xD5, (byte)0x7D, (byte)0x03, (byte)0xDB,
                    (byte)0x95, (byte)0xB9, (byte)0x7A, (byte)0x9B, 
                    (byte)0x79, (byte)0x07, (byte)0xE4, (byte)0xB0, 
                    (byte)0x20, (byte)0x96, (byte)0x04, (byte)0x55, 
                    (byte)0xE4, (byte)0x61, (byte)0x76, (byte)0xF8		
                }, new byte[] {
                    (byte)0xE1, (byte)0x2B, (byte)0xDC, (byte)0x1A, 
                    (byte)0xE2, (byte)0x82, (byte)0x57, (byte)0xEC, 
                    (byte)0x70, (byte)0x3F, (byte)0xCC, (byte)0xF0, 
                    (byte)0x95, (byte)0xEE, (byte)0x8D, (byte)0xF1,
                    (byte)0xC1, (byte)0xAB, (byte)0x76, (byte)0x38, 
                    (byte)0x9F, (byte)0xE6, (byte)0x78, (byte)0xCA, 
                    (byte)0xF7, (byte)0xC6, (byte)0xF8, (byte)0x60, 
                    (byte)0xD5, (byte)0xBB, (byte)0x9C, (byte)0x4F,
                    (byte)0xF3, (byte)0x3C, (byte)0x65, (byte)0x7B, 
                    (byte)0x63, (byte)0x7C, (byte)0x30, (byte)0x6A, 
                    (byte)0xDD, (byte)0x4E, (byte)0xA7, (byte)0x79, 
                    (byte)0x9E, (byte)0xB2, (byte)0x3D, (byte)0x31
                }); 
                if (CAPI.KeySizes.Contains(cipher.KeySizes, 32))
                CAPI.Cipher.KnownTest(cipher, PaddingMode.Any, new byte[] {
                    (byte)0x92, (byte)0xBD, (byte)0x9B, (byte)0x1C, 
                    (byte)0xE5, (byte)0xD1, (byte)0x41, (byte)0x01, 
                    (byte)0x54, (byte)0x45, (byte)0xFB, (byte)0xC9, 
                    (byte)0x5E, (byte)0x4D, (byte)0x0E, (byte)0xF2, 
                    (byte)0x68, (byte)0x20, (byte)0x80, (byte)0xAA, 
                    (byte)0x22, (byte)0x7D, (byte)0x64, (byte)0x2F, 
                    (byte)0x26, (byte)0x87, (byte)0xF9, (byte)0x34, 
                    (byte)0x90, (byte)0x40, (byte)0x55, (byte)0x11,		
                }, new byte[] {
                    (byte)0x73, (byte)0x08, (byte)0x94, (byte)0xD6, 
                    (byte)0x15, (byte)0x8E, (byte)0x17, (byte)0xCC, 
                    (byte)0x16, (byte)0x00, (byte)0x18, (byte)0x5A, 
                    (byte)0x8F, (byte)0x41, (byte)0x1C, (byte)0xAB, 
                    (byte)0xB6, (byte)0xAB, (byte)0x7A, (byte)0xF8, 
                    (byte)0x54, (byte)0x1C, (byte)0xF8, (byte)0x57, 
                    (byte)0x55, (byte)0xB8, (byte)0xEA, (byte)0x27, 
                    (byte)0x23, (byte)0x9F, (byte)0x08, (byte)0xD2,
                    (byte)0x16, (byte)0x66, (byte)0x46, (byte)0xE4,
                }, new byte[] {
                    (byte)0xE1, (byte)0x2B, (byte)0xDC, (byte)0x1A, 
                    (byte)0xE2, (byte)0x82, (byte)0x57, (byte)0xEC, 
                    (byte)0x70, (byte)0x3F, (byte)0xCC, (byte)0xF0, 
                    (byte)0x95, (byte)0xEE, (byte)0x8D, (byte)0xF1, 
                    (byte)0xC1, (byte)0xAB, (byte)0x76, (byte)0x38, 
                    (byte)0x9F, (byte)0xE6, (byte)0x78, (byte)0xCA, 
                    (byte)0xF7, (byte)0xC6, (byte)0xF8, (byte)0x60, 
                    (byte)0xD5, (byte)0xBB, (byte)0x9C, (byte)0x4F,
                    (byte)0xF3, (byte)0x3C, (byte)0x65, (byte)0x7B		
                }); 
            }
            mode = new CipherMode.CFB(new byte[] {
                (byte)0xBE, (byte)0x32, (byte)0x97, (byte)0x13, 
                (byte)0x43, (byte)0xFC, (byte)0x9A, (byte)0x48, 
                (byte)0xA0, (byte)0x2A, (byte)0x88, (byte)0x5F, 
                (byte)0x19, (byte)0x4B, (byte)0x09, (byte)0xA1,
            }, 16);
            // создать режим шифрования
            using (CAPI.Cipher cipher = blockCipher.CreateBlockMode(mode))
            { 
                if (CAPI.KeySizes.Contains(cipher.KeySizes, 32))
                CAPI.Cipher.KnownTest(cipher, PaddingMode.Any, new byte[] {
                    (byte)0xE9, (byte)0xDE, (byte)0xE7, (byte)0x2C, 
                    (byte)0x8F, (byte)0x0C, (byte)0x0F, (byte)0xA6, 
                    (byte)0x2D, (byte)0xDB, (byte)0x49, (byte)0xF4, 
                    (byte)0x6F, (byte)0x73, (byte)0x96, (byte)0x47, 
                    (byte)0x06, (byte)0x07, (byte)0x53, (byte)0x16, 
                    (byte)0xED, (byte)0x24, (byte)0x7A, (byte)0x37, 
                    (byte)0x39, (byte)0xCB, (byte)0xA3, (byte)0x83, 
                    (byte)0x03, (byte)0xA9, (byte)0x8B, (byte)0xF6		
                }, new byte[] {
                    (byte)0xB1, (byte)0x94, (byte)0xBA, (byte)0xC8, 
                    (byte)0x0A, (byte)0x08, (byte)0xF5, (byte)0x3B, 
                    (byte)0x36, (byte)0x6D, (byte)0x00, (byte)0x8E, 
                    (byte)0x58, (byte)0x4A, (byte)0x5D, (byte)0xE4, 
                    (byte)0x85, (byte)0x04, (byte)0xFA, (byte)0x9D, 
                    (byte)0x1B, (byte)0xB6, (byte)0xC7, (byte)0xAC, 
                    (byte)0x25, (byte)0x2E, (byte)0x72, (byte)0xC2, 
                    (byte)0x02, (byte)0xFD, (byte)0xCE, (byte)0x0D,
                    (byte)0x5B, (byte)0xE3, (byte)0xD6, (byte)0x12, 
                    (byte)0x17, (byte)0xB9, (byte)0x61, (byte)0x81, 
                    (byte)0xFE, (byte)0x67, (byte)0x86, (byte)0xAD, 
                    (byte)0x71, (byte)0x6B, (byte)0x89, (byte)0x0B
                }, new byte[] {
                    (byte)0xC3, (byte)0x1E, (byte)0x49, (byte)0x0A, 
                    (byte)0x90, (byte)0xEF, (byte)0xA3, (byte)0x74, 
                    (byte)0x62, (byte)0x6C, (byte)0xC9, (byte)0x9E, 
                    (byte)0x4B, (byte)0x7B, (byte)0x85, (byte)0x40, 
                    (byte)0xA6, (byte)0xE4, (byte)0x86, (byte)0x85, 
                    (byte)0x46, (byte)0x4A, (byte)0x5A, (byte)0x06, 
                    (byte)0x84, (byte)0x9C, (byte)0x9C, (byte)0xA7, 
                    (byte)0x69, (byte)0xA1, (byte)0xB0, (byte)0xAE,
                    (byte)0x55, (byte)0xC2, (byte)0xCC, (byte)0x59, 
                    (byte)0x39, (byte)0x30, (byte)0x3E, (byte)0xC8, 
                    (byte)0x32, (byte)0xDD, (byte)0x2F, (byte)0xE1, 
                    (byte)0x6C, (byte)0x8E, (byte)0x5A, (byte)0x1B
                }); 
            }
            mode = new CipherMode.CFB(new byte[] {
                (byte)0x7E, (byte)0xCD, (byte)0xA4, (byte)0xD0, 
                (byte)0x15, (byte)0x44, (byte)0xAF, (byte)0x8C, 
                (byte)0xA5, (byte)0x84, (byte)0x50, (byte)0xBF, 
                (byte)0x66, (byte)0xD2, (byte)0xE8, (byte)0x8A
            }, 16);
            // создать режим шифрования
            using (CAPI.Cipher cipher = blockCipher.CreateBlockMode(mode))
            { 
                if (CAPI.KeySizes.Contains(cipher.KeySizes, 32))
                CAPI.Cipher.KnownTest(cipher, PaddingMode.Any, new byte[] {
                    (byte)0x92, (byte)0xBD, (byte)0x9B, (byte)0x1C, 
                    (byte)0xE5, (byte)0xD1, (byte)0x41, (byte)0x01, 
                    (byte)0x54, (byte)0x45, (byte)0xFB, (byte)0xC9, 
                    (byte)0x5E, (byte)0x4D, (byte)0x0E, (byte)0xF2, 
                    (byte)0x68, (byte)0x20, (byte)0x80, (byte)0xAA, 
                    (byte)0x22, (byte)0x7D, (byte)0x64, (byte)0x2F, 
                    (byte)0x26, (byte)0x87, (byte)0xF9, (byte)0x34, 
                    (byte)0x90, (byte)0x40, (byte)0x55, (byte)0x11,		
                }, new byte[] {
                    (byte)0xFA, (byte)0x9D, (byte)0x10, (byte)0x7A, 
                    (byte)0x86, (byte)0xF3, (byte)0x75, (byte)0xEE, 
                    (byte)0x65, (byte)0xCD, (byte)0x1D, (byte)0xB8, 
                    (byte)0x81, (byte)0x22, (byte)0x4B, (byte)0xD0, 
                    (byte)0x16, (byte)0xAF, (byte)0xF8, (byte)0x14, 
                    (byte)0x93, (byte)0x8E, (byte)0xD3, (byte)0x9B, 
                    (byte)0x33, (byte)0x61, (byte)0xAB, (byte)0xB0, 
                    (byte)0xBF, (byte)0x08, (byte)0x51, (byte)0xB6,
                    (byte)0x52, (byte)0x24, (byte)0x4E, (byte)0xB0, 
                    (byte)0x68, (byte)0x42, (byte)0xDD, (byte)0x4C, 
                    (byte)0x94, (byte)0xAA, (byte)0x45, (byte)0x00, 
                    (byte)0x77, (byte)0x4E, (byte)0x40, (byte)0xBB		
                }, new byte[] {
                    (byte)0xE1, (byte)0x2B, (byte)0xDC, (byte)0x1A, 
                    (byte)0xE2, (byte)0x82, (byte)0x57, (byte)0xEC, 
                    (byte)0x70, (byte)0x3F, (byte)0xCC, (byte)0xF0, 
                    (byte)0x95, (byte)0xEE, (byte)0x8D, (byte)0xF1,
                    (byte)0xC1, (byte)0xAB, (byte)0x76, (byte)0x38, 
                    (byte)0x9F, (byte)0xE6, (byte)0x78, (byte)0xCA, 
                    (byte)0xF7, (byte)0xC6, (byte)0xF8, (byte)0x60, 
                    (byte)0xD5, (byte)0xBB, (byte)0x9C, (byte)0x4F,
                    (byte)0xF3, (byte)0x3C, (byte)0x65, (byte)0x7B, 
                    (byte)0x63, (byte)0x7C, (byte)0x30, (byte)0x6A, 
                    (byte)0xDD, (byte)0x4E, (byte)0xA7, (byte)0x79, 
                    (byte)0x9E, (byte)0xB2, (byte)0x3D, (byte)0x31
                }); 
            }
            mode = new CipherMode.CTR(new byte[] {
                (byte)0xBE, (byte)0x32, (byte)0x97, (byte)0x13, 
                (byte)0x43, (byte)0xFC, (byte)0x9A, (byte)0x48, 
                (byte)0xA0, (byte)0x2A, (byte)0x88, (byte)0x5F, 
                (byte)0x19, (byte)0x4B, (byte)0x09, (byte)0xA1,
            }, 16);
            // создать режим шифрования
            using (CAPI.Cipher cipher = blockCipher.CreateBlockMode(mode))
            { 
                if (CAPI.KeySizes.Contains(cipher.KeySizes, 32))
                CAPI.Cipher.KnownTest(cipher, PaddingMode.Any, new byte[] {
                    (byte)0xE9, (byte)0xDE, (byte)0xE7, (byte)0x2C, 
                    (byte)0x8F, (byte)0x0C, (byte)0x0F, (byte)0xA6, 
                    (byte)0x2D, (byte)0xDB, (byte)0x49, (byte)0xF4, 
                    (byte)0x6F, (byte)0x73, (byte)0x96, (byte)0x47, 
                    (byte)0x06, (byte)0x07, (byte)0x53, (byte)0x16, 
                    (byte)0xED, (byte)0x24, (byte)0x7A, (byte)0x37, 
                    (byte)0x39, (byte)0xCB, (byte)0xA3, (byte)0x83, 
                    (byte)0x03, (byte)0xA9, (byte)0x8B, (byte)0xF6		
                }, new byte[] {
                    (byte)0xB1, (byte)0x94, (byte)0xBA, (byte)0xC8, 
                    (byte)0x0A, (byte)0x08, (byte)0xF5, (byte)0x3B, 
                    (byte)0x36, (byte)0x6D, (byte)0x00, (byte)0x8E, 
                    (byte)0x58, (byte)0x4A, (byte)0x5D, (byte)0xE4, 
                    (byte)0x85, (byte)0x04, (byte)0xFA, (byte)0x9D, 
                    (byte)0x1B, (byte)0xB6, (byte)0xC7, (byte)0xAC, 
                    (byte)0x25, (byte)0x2E, (byte)0x72, (byte)0xC2, 
                    (byte)0x02, (byte)0xFD, (byte)0xCE, (byte)0x0D,
                    (byte)0x5B, (byte)0xE3, (byte)0xD6, (byte)0x12, 
                    (byte)0x17, (byte)0xB9, (byte)0x61, (byte)0x81, 
                    (byte)0xFE, (byte)0x67, (byte)0x86, (byte)0xAD, 
                    (byte)0x71, (byte)0x6B, (byte)0x89, (byte)0x0B
                }, new byte[] {
                    (byte)0x52, (byte)0xC9, (byte)0xAF, (byte)0x96, 
                    (byte)0xFF, (byte)0x50, (byte)0xF6, (byte)0x44, 
                    (byte)0x35, (byte)0xFC, (byte)0x43, (byte)0xDE, 
                    (byte)0xF5, (byte)0x6B, (byte)0xD7, (byte)0x97, 
                    (byte)0xD5, (byte)0xB5, (byte)0xB1, (byte)0xFF, 
                    (byte)0x79, (byte)0xFB, (byte)0x41, (byte)0x25, 
                    (byte)0x7A, (byte)0xB9, (byte)0xCD, (byte)0xF6, 
                    (byte)0xE6, (byte)0x3E, (byte)0x81, (byte)0xF8,
                    (byte)0xF0, (byte)0x03, (byte)0x41, (byte)0x47, 
                    (byte)0x3E, (byte)0xAE, (byte)0x40, (byte)0x98, 
                    (byte)0x33, (byte)0x62, (byte)0x2D, (byte)0xE0, 
                    (byte)0x52, (byte)0x13, (byte)0x77, (byte)0x3A
                }); 
            }
        }
    }
}
