namespace Aladdin.CAPI.ANSI.Engine
{
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм шифрования Skipjack
    ///////////////////////////////////////////////////////////////////////////
    public class Skipjack : CAPI.Cipher
    {
        // способ кодирования чисел
        private const Math.Endian Endian = Math.Endian.BigEndian; 
    
        // тип ключа
        public override SecretKeyFactory KeyFactory { get { return Keys.Skipjack.Instance; }}
        // размер блока
		public override int BlockSize { get { return 8;	}}

		// алгоритм зашифрования блока данных
		protected override Transform CreateEncryption(ISecretKey key) 
		{
            // проверить тип ключа
            if (key.Value == null) throw new InvalidKeyException();

            // при указании размера ключа
            if (key.Length != 10) throw new InvalidKeyException();

		    // вернуть алгоритм зашифрования блока данных
			return new Encryption(key); 
		}
		// алгоритм расшифрования блока данных
		protected override Transform CreateDecryption(ISecretKey key)
		{
            // проверить тип ключа
            if (key.Value == null) throw new InvalidKeyException();

            // при указании размера ключа
            if (key.Length != 10) throw new InvalidKeyException();

		    // вернуть алгоритм расшифрования блока данных
			return new Decryption(key);
		}
	    ///////////////////////////////////////////////////////////////////////////
	    // Алгоритм зашифрования блока
	    ///////////////////////////////////////////////////////////////////////////
	    public class Encryption : BlockTransform
	    {
		    // число раундов и расписание ключей
            private byte[] key0, key1, key2, key3;

		    // Конструктор
		    public Encryption(ISecretKey key) : base(8)
		    { 
			    // проверить тип ключа
			    byte[] value = key.Value; if (key.Value == null)
			    {
				    // при ошибке выбросить исключение
				    throw new InvalidKeyException();
			    }
                // проверить размер ключа
                if (value.Length != 10) throw new InvalidKeyException(); 

                // выделить память для расписания ключей
                key0 = new byte[32]; key1 = new byte[32]; 
                key2 = new byte[32]; key3 = new byte[32];
            
                // создать расписание ключей
                for (int i = 0; i < 32; i++)
                {
                    key0[i] = value[(i * 4 + 0) % 10]; 
                    key1[i] = value[(i * 4 + 1) % 10];
                    key2[i] = value[(i * 4 + 2) % 10]; 
                    key3[i] = value[(i * 4 + 3) % 10];
                }
		    }
		    // обработка одного блока данных
		    protected override void Update(byte[] src, int srcOff, byte[] dest, int destOff)
		    {
			    // извлечь обрабатываемый блок
			    ushort w1 = Math.Convert.ToUInt16(src, srcOff + 0, Endian); 
			    ushort w2 = Math.Convert.ToUInt16(src, srcOff + 2, Endian);
			    ushort w3 = Math.Convert.ToUInt16(src, srcOff + 4, Endian);
			    ushort w4 = Math.Convert.ToUInt16(src, srcOff + 6, Endian);

                for (int t = 0; t < 2; t++)
                {
                    for (int i = 0, k = 16 * t; i < 8; i++, k++)
                    {
                        ushort g = G(k, w1); ushort w = w4; 
                        w4 = w3; w3 = w2; w2 = g; w1 = (ushort)(g ^ w ^ (k + 1)); 
                    }
                    for (int i = 0, k = 16 * t + 8; i < 8; i++, k++)
                    {
                        ushort g = G(k, w1); ushort w = w4;
                        w4 = w3; w3 = (ushort)(w1 ^ w2 ^ (k + 1)); w2 = g; w1 = w;
                    }
                }
                Math.Convert.FromUInt16(w1, Endian, dest, destOff + 0); 
                Math.Convert.FromUInt16(w2, Endian, dest, destOff + 2); 
                Math.Convert.FromUInt16(w3, Endian, dest, destOff + 4); 
                Math.Convert.FromUInt16(w4, Endian, dest, destOff + 6); 
		    }
            private ushort G(int k, ushort w)
            {
                byte g1 = (byte)(w >> 8); byte g2 = (byte)(w & 0xFF);

                byte g3 = (byte)(Ftable[(g2 ^ key0[k])] ^ g1);
                byte g4 = (byte)(Ftable[(g3 ^ key1[k])] ^ g2);
                byte g5 = (byte)(Ftable[(g4 ^ key2[k])] ^ g3);
                byte g6 = (byte)(Ftable[(g5 ^ key3[k])] ^ g4);

                return (ushort)((g5 << 8) | g6);
            }
	    }
	    ///////////////////////////////////////////////////////////////////////////
	    // Алгоритм расшифрования блока
	    ///////////////////////////////////////////////////////////////////////////
	    public class Decryption : BlockTransform
	    {
		    // число раундов и расписание ключей
            private byte[] key0, key1, key2, key3;

		    // Конструктор
		    public Decryption(ISecretKey key) : base(8)
		    { 
			    // проверить тип ключа
			    byte[] value = key.Value; if (value == null)
			    {
				    // при ошибке выбросить исключение
				    throw new InvalidKeyException();
			    }
                // проверить размер ключа
                if (value.Length != 10) throw new InvalidKeyException(); 

                // выделить память для расписания ключей
                key0 = new byte[32]; key1 = new byte[32]; 
                key2 = new byte[32]; key3 = new byte[32];
            
                // создать расписание ключей
                for (int i = 0; i < 32; i++)
                {
                    key0[i] = value[(i * 4 + 0) % 10]; 
                    key1[i] = value[(i * 4 + 1) % 10];
                    key2[i] = value[(i * 4 + 2) % 10]; 
                    key3[i] = value[(i * 4 + 3) % 10];
                }
		    }
		    // обработка одного блока данных
		    protected override void Update(byte[] src, int srcOff, byte[] dest, int destOff)
		    {
			    // извлечь обрабатываемый блок
			    ushort w2 = Math.Convert.ToUInt16(src, srcOff + 0, Endian); 
			    ushort w1 = Math.Convert.ToUInt16(src, srcOff + 2, Endian);
			    ushort w4 = Math.Convert.ToUInt16(src, srcOff + 4, Endian);
			    ushort w3 = Math.Convert.ToUInt16(src, srcOff + 6, Endian);

                for (int t = 0; t < 2; t++)
                {
                    for (int i = 0, k = 31 - 16 * t; i < 8; i++, k--)
                    {
                        ushort h = H(k, w1); ushort w = w4;
                        w4 = w3; w3 = w2; w2 = h; w1 = (ushort)(w2 ^ w ^ (k + 1));
                    }

                    for (int i = 0, k = 23 - 16 * t; i < 8; i++, k--)
                    {
                        ushort h = H(k, w1); ushort w = w4;
                        w4 = w3; w3 = (ushort)(w1 ^ w2 ^ (k + 1)); w2 = h; w1 = w;
                    }
                }
                Math.Convert.FromUInt16(w2, Endian, dest, destOff + 0); 
                Math.Convert.FromUInt16(w1, Endian, dest, destOff + 2); 
                Math.Convert.FromUInt16(w4, Endian, dest, destOff + 4); 
                Math.Convert.FromUInt16(w3, Endian, dest, destOff + 6); 
		    }
            private ushort H(int k, ushort w)
            {
                byte h1 = (byte)(w & 0xFF); byte h2 = (byte)(w >> 8); 

                byte h3 = (byte)(Ftable[(h2 ^ key3[k])] ^ h1);
                byte h4 = (byte)(Ftable[(h3 ^ key2[k])] ^ h2);
                byte h5 = (byte)(Ftable[(h4 ^ key1[k])] ^ h3);
                byte h6 = (byte)(Ftable[(h5 ^ key0[k])] ^ h4);

                return (ushort)((h6 << 8) | h5);
            }
	    }
        ///////////////////////////////////////////////////////////////////////////
        // Вспомогательные таблицы
        ///////////////////////////////////////////////////////////////////////////
        private static readonly byte[] Ftable =
        {
            (byte)0xa3, (byte)0xd7, (byte)0x09, (byte)0x83, 
            (byte)0xf8, (byte)0x48, (byte)0xf6, (byte)0xf4, 
            (byte)0xb3, (byte)0x21, (byte)0x15, (byte)0x78, 
            (byte)0x99, (byte)0xb1, (byte)0xaf, (byte)0xf9,
            (byte)0xe7, (byte)0x2d, (byte)0x4d, (byte)0x8a, 
            (byte)0xce, (byte)0x4c, (byte)0xca, (byte)0x2e, 
            (byte)0x52, (byte)0x95, (byte)0xd9, (byte)0x1e, 
            (byte)0x4e, (byte)0x38, (byte)0x44, (byte)0x28,
            (byte)0x0a, (byte)0xdf, (byte)0x02, (byte)0xa0, 
            (byte)0x17, (byte)0xf1, (byte)0x60, (byte)0x68, 
            (byte)0x12, (byte)0xb7, (byte)0x7a, (byte)0xc3, 
            (byte)0xe9, (byte)0xfa, (byte)0x3d, (byte)0x53,
            (byte)0x96, (byte)0x84, (byte)0x6b, (byte)0xba, 
            (byte)0xf2, (byte)0x63, (byte)0x9a, (byte)0x19, 
            (byte)0x7c, (byte)0xae, (byte)0xe5, (byte)0xf5, 
            (byte)0xf7, (byte)0x16, (byte)0x6a, (byte)0xa2,
            (byte)0x39, (byte)0xb6, (byte)0x7b, (byte)0x0f, 
            (byte)0xc1, (byte)0x93, (byte)0x81, (byte)0x1b, 
            (byte)0xee, (byte)0xb4, (byte)0x1a, (byte)0xea, 
            (byte)0xd0, (byte)0x91, (byte)0x2f, (byte)0xb8,
            (byte)0x55, (byte)0xb9, (byte)0xda, (byte)0x85, 
            (byte)0x3f, (byte)0x41, (byte)0xbf, (byte)0xe0, 
            (byte)0x5a, (byte)0x58, (byte)0x80, (byte)0x5f, 
            (byte)0x66, (byte)0x0b, (byte)0xd8, (byte)0x90,
            (byte)0x35, (byte)0xd5, (byte)0xc0, (byte)0xa7, 
            (byte)0x33, (byte)0x06, (byte)0x65, (byte)0x69, 
            (byte)0x45, (byte)0x00, (byte)0x94, (byte)0x56, 
            (byte)0x6d, (byte)0x98, (byte)0x9b, (byte)0x76,
            (byte)0x97, (byte)0xfc, (byte)0xb2, (byte)0xc2, 
            (byte)0xb0, (byte)0xfe, (byte)0xdb, (byte)0x20, 
            (byte)0xe1, (byte)0xeb, (byte)0xd6, (byte)0xe4, 
            (byte)0xdd, (byte)0x47, (byte)0x4a, (byte)0x1d,
            (byte)0x42, (byte)0xed, (byte)0x9e, (byte)0x6e, 
            (byte)0x49, (byte)0x3c, (byte)0xcd, (byte)0x43, 
            (byte)0x27, (byte)0xd2, (byte)0x07, (byte)0xd4, 
            (byte)0xde, (byte)0xc7, (byte)0x67, (byte)0x18,
            (byte)0x89, (byte)0xcb, (byte)0x30, (byte)0x1f, 
            (byte)0x8d, (byte)0xc6, (byte)0x8f, (byte)0xaa, 
            (byte)0xc8, (byte)0x74, (byte)0xdc, (byte)0xc9, 
            (byte)0x5d, (byte)0x5c, (byte)0x31, (byte)0xa4,
            (byte)0x70, (byte)0x88, (byte)0x61, (byte)0x2c, 
            (byte)0x9f, (byte)0x0d, (byte)0x2b, (byte)0x87, 
            (byte)0x50, (byte)0x82, (byte)0x54, (byte)0x64, 
            (byte)0x26, (byte)0x7d, (byte)0x03, (byte)0x40,
            (byte)0x34, (byte)0x4b, (byte)0x1c, (byte)0x73, 
            (byte)0xd1, (byte)0xc4, (byte)0xfd, (byte)0x3b, 
            (byte)0xcc, (byte)0xfb, (byte)0x7f, (byte)0xab, 
            (byte)0xe6, (byte)0x3e, (byte)0x5b, (byte)0xa5,
            (byte)0xad, (byte)0x04, (byte)0x23, (byte)0x9c, 
            (byte)0x14, (byte)0x51, (byte)0x22, (byte)0xf0, 
            (byte)0x29, (byte)0x79, (byte)0x71, (byte)0x7e, 
            (byte)0xff, (byte)0x8c, (byte)0x0e, (byte)0xe2,
            (byte)0x0c, (byte)0xef, (byte)0xbc, (byte)0x72, 
            (byte)0x75, (byte)0x6f, (byte)0x37, (byte)0xa1, 
            (byte)0xec, (byte)0xd3, (byte)0x8e, (byte)0x62, 
            (byte)0x8b, (byte)0x86, (byte)0x10, (byte)0xe8,
            (byte)0x08, (byte)0x77, (byte)0x11, (byte)0xbe, 
            (byte)0x92, (byte)0x4f, (byte)0x24, (byte)0xc5, 
            (byte)0x32, (byte)0x36, (byte)0x9d, (byte)0xcf, 
            (byte)0xf3, (byte)0xa6, (byte)0xbb, (byte)0xac,
            (byte)0x5e, (byte)0x6c, (byte)0xa9, (byte)0x13, 
            (byte)0x57, (byte)0x25, (byte)0xb5, (byte)0xe3, 
            (byte)0xbd, (byte)0xa8, (byte)0x3a, (byte)0x01, 
            (byte)0x05, (byte)0x59, (byte)0x2a, (byte)0x46
        };
        ////////////////////////////////////////////////////////////////////////////
        // Тест известного ответа
        ////////////////////////////////////////////////////////////////////////////
        public static void Test(CAPI.Cipher cipher) 
        {
            // выполнить тест
            CAPI.Cipher.KnownTest(cipher, PaddingMode.None, new byte[] {
                (byte)0x00, (byte)0x99, (byte)0x88, (byte)0x77,
                (byte)0x66, (byte)0x55, (byte)0x44, (byte)0x33,
                (byte)0x22, (byte)0x11,
            }, new byte[] {
                (byte)0x33, (byte)0x22, (byte)0x11, (byte)0x00,
                (byte)0xDD, (byte)0xCC, (byte)0xBB, (byte)0xAA
            }, new byte[] {
                (byte)0x25, (byte)0x87, (byte)0xCA, (byte)0xE2,
                (byte)0x7A, (byte)0x12, (byte)0xD3, (byte)0x00
            }); 
        }
    }
}