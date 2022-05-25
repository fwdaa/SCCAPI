using System; 

namespace Aladdin.CAPI.ANSI.Engine
{
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм шифрования TDES
    ///////////////////////////////////////////////////////////////////////////
    public class TDES : CAPI.Cipher
    {
        // преобразование DES и размеры ключей
        private CAPI.Cipher des; private int[] keySizes; 
        
		// конструктор
		public TDES(CAPI.Cipher des, int[] keySizes) 
        { 
            // сохранить переданные параметры
            this.des = RefObject.AddRef(des); this.keySizes = keySizes; 
        }
        // освободить ресурсы 
        protected override void OnDispose()
        {
            // освободить ресурсы 
            RefObject.Release(des); base.OnDispose();
        }
        // тип ключа
        public override SecretKeyFactory KeyFactory 
        { 
            // тип ключа
            get { return new Keys.TDES(keySizes); }
        }
        // размер блока
		public override int BlockSize { get { return des.BlockSize; }}

		// алгоритм зашифрования блока данных
		protected override Transform CreateEncryption(ISecretKey key) 
		{
            // проверить тип ключа
            if (key.Value == null) throw new InvalidKeyException();

            // проверить размер ключа
            if (key.Length != 16 && key.Length != 24) 
            {
                // при ошибке выбросить исключение
                throw new InvalidKeyException();
            }
		    // вернуть алгоритм зашифрования блока данных
		    return new Encryption(des, key); 
		}
		// алгоритм расшифрования блока данных
		protected override Transform CreateDecryption(ISecretKey key)
		{
            // проверить тип ключа
            if (key.Value == null) throw new InvalidKeyException();

            // проверить размер ключа
            if (key.Length != 16 && key.Length != 24) 
            {
                // при ошибке выбросить исключение
                throw new InvalidKeyException();
            }
		    // вернуть алгоритм расшифрования блока данных
		    return new Decryption(des, key);
		}
	    ///////////////////////////////////////////////////////////////////////////
	    // Алгоритм зашифрования блока
	    ///////////////////////////////////////////////////////////////////////////
	    public class Encryption : BlockTransform
	    {
		    // используемые преобразования
		    private Transform[] transforms; 

		    // Конструктор
		    public Encryption(CAPI.Cipher des, ISecretKey key) : base(8)
		    { 
			    // проверить тип ключа
			    byte[] value = key.Value; if (value == null)
			    {
				    // при ошибке выбросить исключение
				    throw new InvalidKeyException();
			    }
                // проверить размер ключа
                if (value.Length != 16 && value.Length != 24)
                {
                    // при ошибке выбросить исключение
                    throw new InvalidKeyException();
                }
                // сохранить переданные параметры
                transforms = new Transform[3]; switch (value.Length)
                {
                case 16:
                {
                    // извлечь используемые ключи
                    byte[] key1 = new byte[8]; Array.Copy(value, 0, key1, 0, 8); 
                    byte[] key2 = new byte[8]; Array.Copy(value, 8, key2, 0, 8);
                
                    // указать используемые преобразования
                    using (ISecretKey k1 = des.KeyFactory.Create(key1)) 
                    {
                        transforms[0] = des.CreateEncryption(k1, PaddingMode.None); 
                        transforms[0].Init(); 
                    }
                    using (ISecretKey k2 = des.KeyFactory.Create(key2)) 
                    {
                        transforms[1] = des.CreateDecryption(k2, PaddingMode.None);
                        transforms[1].Init(); 
                    }
                    // указать используемые преобразования
                    transforms[2] = RefObject.AddRef(transforms[0]); break; 
                }
                case 24:
                {
                    // извлечь используемые ключи
                    byte[] key1 = new byte[8]; Array.Copy(value,  0, key1, 0, 8); 
                    byte[] key2 = new byte[8]; Array.Copy(value,  8, key2, 0, 8);
                    byte[] key3 = new byte[8]; Array.Copy(value, 16, key3, 0, 8);
                
                    // указать используемые преобразования
                    using (ISecretKey k1 = des.KeyFactory.Create(key1)) 
                    {
                        transforms[0] = des.CreateEncryption(k1, PaddingMode.None); 
                        transforms[0].Init(); 
                    }
                    using (ISecretKey k2 = des.KeyFactory.Create(key2)) 
                    {
                        transforms[1] = des.CreateDecryption(k2, PaddingMode.None);
                        transforms[1].Init(); 
                    }
                    using (ISecretKey k3 = des.KeyFactory.Create(key3)) 
                    {
                        transforms[2] = des.CreateEncryption(k3, PaddingMode.None); 
                        transforms[2].Init(); 
                    }
                    break;  
                }}
		    }
            // освободить ресурсы 
            protected override void OnDispose()
            {
                // освободить ресурсы 
                RefObject.Release(transforms[2]); RefObject.Release(transforms[1]); 
                
                // освободить ресурсы 
                RefObject.Release(transforms[0]); base.OnDispose();
            }
		    // обработка одного блока данных
		    protected override void Update(byte[] src, int srcOff, byte[] dest, int destOff)
		    {
                transforms[0].Update(src , srcOff , 8, dest, destOff); 
                transforms[1].Update(dest, destOff, 8, dest, destOff); 
                transforms[2].Update(dest, destOff, 8, dest, destOff); 
            }
	    }
	    ///////////////////////////////////////////////////////////////////////////
	    // Алгоритм расшифрования блока
	    ///////////////////////////////////////////////////////////////////////////
	    public class Decryption : BlockTransform
	    {
		    // используемые преобразования
		    private Transform[] transforms; 

		    // Конструктор
		    public Decryption(CAPI.Cipher des, ISecretKey key) : base(8)
		    { 
			    // проверить тип ключа
			    byte[] value = key.Value; if (value == null)
			    {
				    // при ошибке выбросить исключение
				    throw new InvalidKeyException();
			    }
                // проверить размер ключа
                if (value.Length != 16 && value.Length != 24)
                {
                    // при ошибке выбросить исключение
                    throw new InvalidKeyException();
                }
                // сохранить переданные параметры
                transforms = new Transform[3]; switch (value.Length)
                {
                case 16:
                {
                    // извлечь используемые ключи
                    byte[] key1 = new byte[8]; Array.Copy(value, 0, key1, 0, 8); 
                    byte[] key2 = new byte[8]; Array.Copy(value, 8, key2, 0, 8);
                
                    // указать используемые преобразования
                    using (ISecretKey k1 = des.KeyFactory.Create(key1)) 
                    {
                        transforms[0] = des.CreateDecryption(k1, PaddingMode.None); 
                        transforms[0].Init(); 
                    }
                    using (ISecretKey k2 = des.KeyFactory.Create(key2)) 
                    {
                        transforms[1] = des.CreateEncryption(k2, PaddingMode.None);
                        transforms[1].Init(); 
                    }
                    // указать используемые преобразования
                    transforms[2] = RefObject.AddRef(transforms[0]); break; 
                }
                case 24:
                {
                    // извлечь используемые ключи
                    byte[] key1 = new byte[8]; Array.Copy(value,  0, key1, 0, 8); 
                    byte[] key2 = new byte[8]; Array.Copy(value,  8, key2, 0, 8);
                    byte[] key3 = new byte[8]; Array.Copy(value, 16, key3, 0, 8);
                
                    // указать используемые преобразования
                    using (ISecretKey k3 = des.KeyFactory.Create(key3)) 
                    {
                        transforms[0] = des.CreateDecryption(k3, PaddingMode.None); 
                        transforms[0].Init(); 
                    }
                    using (ISecretKey k2 = des.KeyFactory.Create(key2)) 
                    {
                        transforms[1] = des.CreateEncryption(k2, PaddingMode.None);
                        transforms[1].Init(); 
                    }
                    using (ISecretKey k1 = des.KeyFactory.Create(key1)) 
                    {
                        transforms[2] = des.CreateDecryption(k1, PaddingMode.None); 
                        transforms[2].Init(); 
                    }
                    break;  
                }}
		    }
            // освободить ресурсы 
            protected override void OnDispose()
            {
                // освободить ресурсы 
                RefObject.Release(transforms[2]); RefObject.Release(transforms[1]); 
                
                // освободить ресурсы 
                RefObject.Release(transforms[0]); base.OnDispose();
            }
		    // обработка одного блока данных
		    protected override void Update(byte[] src, int srcOff, byte[] dest, int destOff)
		    {
                transforms[0].Update(src , srcOff , 8, dest, destOff); 
                transforms[1].Update(dest, destOff, 8, dest, destOff); 
                transforms[2].Update(dest, destOff, 8, dest, destOff); 
		    }
	    }
        ////////////////////////////////////////////////////////////////////////////
        // Тесты известного ответа
        ////////////////////////////////////////////////////////////////////////////
        public static void Test(CAPI.Cipher engine)
        {
            int[] keySizes = engine.KeyFactory.KeySizes; 

            if (CAPI.KeySizes.Contains(keySizes, 16))
            CAPI.Cipher.KnownTest(engine, PaddingMode.None, new byte[] {
                (byte)0x7c, (byte)0xa1, (byte)0x10, (byte)0x45, 
                (byte)0x4a, (byte)0x1a, (byte)0x6e, (byte)0x57, 
                (byte)0x7c, (byte)0xa1, (byte)0x10, (byte)0x45, 
                (byte)0x4a, (byte)0x1a, (byte)0x6e, (byte)0x57, 
            }, new byte[] {
                (byte)0x01, (byte)0xa1, (byte)0xd6, (byte)0xd0, 
                (byte)0x39, (byte)0x77, (byte)0x67, (byte)0x42, 
            }, new byte[] {
                (byte)0x69, (byte)0x0f, (byte)0x5b, (byte)0x0d, 
                (byte)0x9a, (byte)0x26, (byte)0x93, (byte)0x9b, 
            }); 
            if (CAPI.KeySizes.Contains(keySizes, 24))
            CAPI.Cipher.KnownTest(engine, PaddingMode.None, new byte[] {
                (byte)0x7c, (byte)0xa1, (byte)0x10, (byte)0x45, 
                (byte)0x4a, (byte)0x1a, (byte)0x6e, (byte)0x57, 
                (byte)0x7c, (byte)0xa1, (byte)0x10, (byte)0x45, 
                (byte)0x4a, (byte)0x1a, (byte)0x6e, (byte)0x57, 
                (byte)0x7c, (byte)0xa1, (byte)0x10, (byte)0x45, 
                (byte)0x4a, (byte)0x1a, (byte)0x6e, (byte)0x57, 
            }, new byte[] {
                (byte)0x01, (byte)0xa1, (byte)0xd6, (byte)0xd0, 
                (byte)0x39, (byte)0x77, (byte)0x67, (byte)0x42, 
            }, new byte[] {
                (byte)0x69, (byte)0x0f, (byte)0x5b, (byte)0x0d, 
                (byte)0x9a, (byte)0x26, (byte)0x93, (byte)0x9b, 
            }); 
            if (CAPI.KeySizes.Contains(keySizes, 16))
            CAPI.Cipher.KnownTest(engine, PaddingMode.None, new byte[] {
                (byte)0x01, (byte)0x31, (byte)0xd9, (byte)0x61, 
                (byte)0x9d, (byte)0xc1, (byte)0x37, (byte)0x6e, 
                (byte)0x01, (byte)0x31, (byte)0xd9, (byte)0x61, 
                (byte)0x9d, (byte)0xc1, (byte)0x37, (byte)0x6e, 
            }, new byte[] {
                (byte)0x5c, (byte)0xd5, (byte)0x4c, (byte)0xa8, 
                (byte)0x3d, (byte)0xef, (byte)0x57, (byte)0xda, 
            }, new byte[] {
                (byte)0x7a, (byte)0x38, (byte)0x9d, (byte)0x10, 
                (byte)0x35, (byte)0x4b, (byte)0xd2, (byte)0x71, 
            }); 
            if (CAPI.KeySizes.Contains(keySizes, 24))
            CAPI.Cipher.KnownTest(engine, PaddingMode.None, new byte[] {
                (byte)0x01, (byte)0x31, (byte)0xd9, (byte)0x61, 
                (byte)0x9d, (byte)0xc1, (byte)0x37, (byte)0x6e, 
                (byte)0x01, (byte)0x31, (byte)0xd9, (byte)0x61, 
                (byte)0x9d, (byte)0xc1, (byte)0x37, (byte)0x6e, 
                (byte)0x01, (byte)0x31, (byte)0xd9, (byte)0x61, 
                (byte)0x9d, (byte)0xc1, (byte)0x37, (byte)0x6e, 
            }, new byte[] {
                (byte)0x5c, (byte)0xd5, (byte)0x4c, (byte)0xa8, 
                (byte)0x3d, (byte)0xef, (byte)0x57, (byte)0xda, 
            }, new byte[] {
                (byte)0x7a, (byte)0x38, (byte)0x9d, (byte)0x10, 
                (byte)0x35, (byte)0x4b, (byte)0xd2, (byte)0x71, 
            }); 
            if (CAPI.KeySizes.Contains(keySizes, 16))
            CAPI.Cipher.KnownTest(engine, PaddingMode.None, new byte[] {
                (byte)0x07, (byte)0xa1, (byte)0x13, (byte)0x3e, 
                (byte)0x4a, (byte)0x0b, (byte)0x26, (byte)0x86, 
                (byte)0x07, (byte)0xa1, (byte)0x13, (byte)0x3e, 
                (byte)0x4a, (byte)0x0b, (byte)0x26, (byte)0x86, 
            }, new byte[] {
                (byte)0x02, (byte)0x48, (byte)0xd4, (byte)0x38, 
                (byte)0x06, (byte)0xf6, (byte)0x71, (byte)0x72, 
            }, new byte[] {
                (byte)0x86, (byte)0x8e, (byte)0xbb, (byte)0x51, 
                (byte)0xca, (byte)0xb4, (byte)0x59, (byte)0x9a, 
            }); 
            if (CAPI.KeySizes.Contains(keySizes, 24))
            CAPI.Cipher.KnownTest(engine, PaddingMode.None, new byte[] {
                (byte)0x07, (byte)0xa1, (byte)0x13, (byte)0x3e, 
                (byte)0x4a, (byte)0x0b, (byte)0x26, (byte)0x86, 
                (byte)0x07, (byte)0xa1, (byte)0x13, (byte)0x3e, 
                (byte)0x4a, (byte)0x0b, (byte)0x26, (byte)0x86, 
                (byte)0x07, (byte)0xa1, (byte)0x13, (byte)0x3e, 
                (byte)0x4a, (byte)0x0b, (byte)0x26, (byte)0x86, 
            }, new byte[] {
                (byte)0x02, (byte)0x48, (byte)0xd4, (byte)0x38, 
                (byte)0x06, (byte)0xf6, (byte)0x71, (byte)0x72, 
            }, new byte[] {
                (byte)0x86, (byte)0x8e, (byte)0xbb, (byte)0x51, 
                (byte)0xca, (byte)0xb4, (byte)0x59, (byte)0x9a, 
            }); 
            if (CAPI.KeySizes.Contains(keySizes, 16))
            CAPI.Cipher.KnownTest(engine, PaddingMode.None, new byte[] {
                (byte)0x38, (byte)0x49, (byte)0x67, (byte)0x4c, 
                (byte)0x26, (byte)0x02, (byte)0x31, (byte)0x9e, 
                (byte)0x38, (byte)0x49, (byte)0x67, (byte)0x4c, 
                (byte)0x26, (byte)0x02, (byte)0x31, (byte)0x9e, 
            }, new byte[] {
                (byte)0x51, (byte)0x45, (byte)0x4b, (byte)0x58, 
                (byte)0x2d, (byte)0xdf, (byte)0x44, (byte)0x0a, 
            }, new byte[] {
                (byte)0x71, (byte)0x78, (byte)0x87, (byte)0x6e, 
                (byte)0x01, (byte)0xf1, (byte)0x9b, (byte)0x2a, 
            }); 
            if (CAPI.KeySizes.Contains(keySizes, 24))
            CAPI.Cipher.KnownTest(engine, PaddingMode.None, new byte[] {
                (byte)0x38, (byte)0x49, (byte)0x67, (byte)0x4c, 
                (byte)0x26, (byte)0x02, (byte)0x31, (byte)0x9e, 
                (byte)0x38, (byte)0x49, (byte)0x67, (byte)0x4c, 
                (byte)0x26, (byte)0x02, (byte)0x31, (byte)0x9e, 
                (byte)0x38, (byte)0x49, (byte)0x67, (byte)0x4c, 
                (byte)0x26, (byte)0x02, (byte)0x31, (byte)0x9e, 
            }, new byte[] {
                (byte)0x51, (byte)0x45, (byte)0x4b, (byte)0x58, 
                (byte)0x2d, (byte)0xdf, (byte)0x44, (byte)0x0a, 
            }, new byte[] {
                (byte)0x71, (byte)0x78, (byte)0x87, (byte)0x6e, 
                (byte)0x01, (byte)0xf1, (byte)0x9b, (byte)0x2a, 
            }); 
            if (CAPI.KeySizes.Contains(keySizes, 16))
            CAPI.Cipher.KnownTest(engine, PaddingMode.None, new byte[] {
                (byte)0x04, (byte)0xb9, (byte)0x15, (byte)0xba, 
                (byte)0x43, (byte)0xfe, (byte)0xb5, (byte)0xb6, 
                (byte)0x04, (byte)0xb9, (byte)0x15, (byte)0xba, 
                (byte)0x43, (byte)0xfe, (byte)0xb5, (byte)0xb6, 
            }, new byte[] {
                (byte)0x42, (byte)0xfd, (byte)0x44, (byte)0x30, 
                (byte)0x59, (byte)0x57, (byte)0x7f, (byte)0xa2, 
            }, new byte[] {
                (byte)0xaf, (byte)0x37, (byte)0xfb, (byte)0x42, 
                (byte)0x1f, (byte)0x8c, (byte)0x40, (byte)0x95, 
            }); 
            if (CAPI.KeySizes.Contains(keySizes, 24))
            CAPI.Cipher.KnownTest(engine, PaddingMode.None, new byte[] {
                (byte)0x04, (byte)0xb9, (byte)0x15, (byte)0xba, 
                (byte)0x43, (byte)0xfe, (byte)0xb5, (byte)0xb6, 
                (byte)0x04, (byte)0xb9, (byte)0x15, (byte)0xba, 
                (byte)0x43, (byte)0xfe, (byte)0xb5, (byte)0xb6, 
                (byte)0x04, (byte)0xb9, (byte)0x15, (byte)0xba, 
                (byte)0x43, (byte)0xfe, (byte)0xb5, (byte)0xb6, 
            }, new byte[] {
                (byte)0x42, (byte)0xfd, (byte)0x44, (byte)0x30, 
                (byte)0x59, (byte)0x57, (byte)0x7f, (byte)0xa2, 
            }, new byte[] {
                (byte)0xaf, (byte)0x37, (byte)0xfb, (byte)0x42, 
                (byte)0x1f, (byte)0x8c, (byte)0x40, (byte)0x95, 
            }); 
            if (CAPI.KeySizes.Contains(keySizes, 16))
            CAPI.Cipher.KnownTest(engine, PaddingMode.None, new byte[] {
                (byte)0x01, (byte)0x13, (byte)0xb9, (byte)0x70, 
                (byte)0xfd, (byte)0x34, (byte)0xf2, (byte)0xce, 
                (byte)0x01, (byte)0x13, (byte)0xb9, (byte)0x70, 
                (byte)0xfd, (byte)0x34, (byte)0xf2, (byte)0xce, 
            }, new byte[] {
                (byte)0x05, (byte)0x9b, (byte)0x5e, (byte)0x08, 
                (byte)0x51, (byte)0xcf, (byte)0x14, (byte)0x3a, 
            }, new byte[] {
                (byte)0x86, (byte)0xa5, (byte)0x60, (byte)0xf1, 
                (byte)0x0e, (byte)0xc6, (byte)0xd8, (byte)0x5b, 
            }); 
            if (CAPI.KeySizes.Contains(keySizes, 24))
            CAPI.Cipher.KnownTest(engine, PaddingMode.None, new byte[] {
                (byte)0x01, (byte)0x13, (byte)0xb9, (byte)0x70, 
                (byte)0xfd, (byte)0x34, (byte)0xf2, (byte)0xce, 
                (byte)0x01, (byte)0x13, (byte)0xb9, (byte)0x70, 
                (byte)0xfd, (byte)0x34, (byte)0xf2, (byte)0xce, 
                (byte)0x01, (byte)0x13, (byte)0xb9, (byte)0x70, 
                (byte)0xfd, (byte)0x34, (byte)0xf2, (byte)0xce, 
            }, new byte[] {
                (byte)0x05, (byte)0x9b, (byte)0x5e, (byte)0x08, 
                (byte)0x51, (byte)0xcf, (byte)0x14, (byte)0x3a, 
            }, new byte[] {
                (byte)0x86, (byte)0xa5, (byte)0x60, (byte)0xf1, 
                (byte)0x0e, (byte)0xc6, (byte)0xd8, (byte)0x5b, 
            }); 
            if (CAPI.KeySizes.Contains(keySizes, 16))
            CAPI.Cipher.KnownTest(engine, PaddingMode.None, new byte[] {
                (byte)0x01, (byte)0x70, (byte)0xf1, (byte)0x75, 
                (byte)0x46, (byte)0x8f, (byte)0xb5, (byte)0xe6, 
                (byte)0x01, (byte)0x70, (byte)0xf1, (byte)0x75, 
                (byte)0x46, (byte)0x8f, (byte)0xb5, (byte)0xe6, 
            }, new byte[] {
                (byte)0x07, (byte)0x56, (byte)0xd8, (byte)0xe0, 
                (byte)0x77, (byte)0x47, (byte)0x61, (byte)0xd2, 
            }, new byte[] {
                (byte)0x0c, (byte)0xd3, (byte)0xda, (byte)0x02, 
                (byte)0x00, (byte)0x21, (byte)0xdc, (byte)0x09, 
            }); 
            if (CAPI.KeySizes.Contains(keySizes, 24))
            CAPI.Cipher.KnownTest(engine, PaddingMode.None, new byte[] {
                (byte)0x01, (byte)0x70, (byte)0xf1, (byte)0x75, 
                (byte)0x46, (byte)0x8f, (byte)0xb5, (byte)0xe6, 
                (byte)0x01, (byte)0x70, (byte)0xf1, (byte)0x75, 
                (byte)0x46, (byte)0x8f, (byte)0xb5, (byte)0xe6, 
                (byte)0x01, (byte)0x70, (byte)0xf1, (byte)0x75, 
                (byte)0x46, (byte)0x8f, (byte)0xb5, (byte)0xe6, 
            }, new byte[] {
                (byte)0x07, (byte)0x56, (byte)0xd8, (byte)0xe0, 
                (byte)0x77, (byte)0x47, (byte)0x61, (byte)0xd2, 
            }, new byte[] {
                (byte)0x0c, (byte)0xd3, (byte)0xda, (byte)0x02, 
                (byte)0x00, (byte)0x21, (byte)0xdc, (byte)0x09, 
            }); 
            if (CAPI.KeySizes.Contains(keySizes, 16))
            CAPI.Cipher.KnownTest(engine, PaddingMode.None, new byte[] {
                (byte)0x43, (byte)0x29, (byte)0x7f, (byte)0xad, 
                (byte)0x38, (byte)0xe3, (byte)0x73, (byte)0xfe, 
                (byte)0x43, (byte)0x29, (byte)0x7f, (byte)0xad, 
                (byte)0x38, (byte)0xe3, (byte)0x73, (byte)0xfe, 
            }, new byte[] {
                (byte)0x76, (byte)0x25, (byte)0x14, (byte)0xb8, 
                (byte)0x29, (byte)0xbf, (byte)0x48, (byte)0x6a, 
            }, new byte[] {
                (byte)0xea, (byte)0x67, (byte)0x6b, (byte)0x2c, 
                (byte)0xb7, (byte)0xdb, (byte)0x2b, (byte)0x7a, 
            }); 
            if (CAPI.KeySizes.Contains(keySizes, 24))
            CAPI.Cipher.KnownTest(engine, PaddingMode.None, new byte[] {
                (byte)0x43, (byte)0x29, (byte)0x7f, (byte)0xad, 
                (byte)0x38, (byte)0xe3, (byte)0x73, (byte)0xfe, 
                (byte)0x43, (byte)0x29, (byte)0x7f, (byte)0xad, 
                (byte)0x38, (byte)0xe3, (byte)0x73, (byte)0xfe, 
                (byte)0x43, (byte)0x29, (byte)0x7f, (byte)0xad, 
                (byte)0x38, (byte)0xe3, (byte)0x73, (byte)0xfe, 
            }, new byte[] {
                (byte)0x76, (byte)0x25, (byte)0x14, (byte)0xb8, 
                (byte)0x29, (byte)0xbf, (byte)0x48, (byte)0x6a, 
            }, new byte[] {
                (byte)0xea, (byte)0x67, (byte)0x6b, (byte)0x2c, 
                (byte)0xb7, (byte)0xdb, (byte)0x2b, (byte)0x7a, 
            }); 
            if (CAPI.KeySizes.Contains(keySizes, 16))
            CAPI.Cipher.KnownTest(engine, PaddingMode.None, new byte[] {
                (byte)0x07, (byte)0xa7, (byte)0x13, (byte)0x70, 
                (byte)0x45, (byte)0xda, (byte)0x2a, (byte)0x16, 
                (byte)0x07, (byte)0xa7, (byte)0x13, (byte)0x70, 
                (byte)0x45, (byte)0xda, (byte)0x2a, (byte)0x16, 
            }, new byte[] {
                (byte)0x3b, (byte)0xdd, (byte)0x11, (byte)0x90, 
                (byte)0x49, (byte)0x37, (byte)0x28, (byte)0x02, 
            }, new byte[] {
                (byte)0xdf, (byte)0xd6, (byte)0x4a, (byte)0x81, 
                (byte)0x5c, (byte)0xaf, (byte)0x1a, (byte)0x0f, 
            }); 
            if (CAPI.KeySizes.Contains(keySizes, 24))
            CAPI.Cipher.KnownTest(engine, PaddingMode.None, new byte[] {
                (byte)0x07, (byte)0xa7, (byte)0x13, (byte)0x70, 
                (byte)0x45, (byte)0xda, (byte)0x2a, (byte)0x16, 
                (byte)0x07, (byte)0xa7, (byte)0x13, (byte)0x70, 
                (byte)0x45, (byte)0xda, (byte)0x2a, (byte)0x16, 
                (byte)0x07, (byte)0xa7, (byte)0x13, (byte)0x70, 
                (byte)0x45, (byte)0xda, (byte)0x2a, (byte)0x16, 
            }, new byte[] {
                (byte)0x3b, (byte)0xdd, (byte)0x11, (byte)0x90, 
                (byte)0x49, (byte)0x37, (byte)0x28, (byte)0x02, 
            }, new byte[] {
                (byte)0xdf, (byte)0xd6, (byte)0x4a, (byte)0x81, 
                (byte)0x5c, (byte)0xaf, (byte)0x1a, (byte)0x0f, 
            }); 
            if (CAPI.KeySizes.Contains(keySizes, 16))
            CAPI.Cipher.KnownTest(engine, PaddingMode.None, new byte[] {
                (byte)0x04, (byte)0x68, (byte)0x91, (byte)0x04, 
                (byte)0xc2, (byte)0xfd, (byte)0x3b, (byte)0x2f, 
                (byte)0x04, (byte)0x68, (byte)0x91, (byte)0x04, 
                (byte)0xc2, (byte)0xfd, (byte)0x3b, (byte)0x2f, 
            }, new byte[] {
                (byte)0x26, (byte)0x95, (byte)0x5f, (byte)0x68, 
                (byte)0x35, (byte)0xaf, (byte)0x60, (byte)0x9a, 
            }, new byte[] {
                (byte)0x5c, (byte)0x51, (byte)0x3c, (byte)0x9c, 
                (byte)0x48, (byte)0x86, (byte)0xc0, (byte)0x88, 
            }); 
            if (CAPI.KeySizes.Contains(keySizes, 24))
            CAPI.Cipher.KnownTest(engine, PaddingMode.None, new byte[] {
                (byte)0x04, (byte)0x68, (byte)0x91, (byte)0x04, 
                (byte)0xc2, (byte)0xfd, (byte)0x3b, (byte)0x2f, 
                (byte)0x04, (byte)0x68, (byte)0x91, (byte)0x04, 
                (byte)0xc2, (byte)0xfd, (byte)0x3b, (byte)0x2f, 
                (byte)0x04, (byte)0x68, (byte)0x91, (byte)0x04, 
                (byte)0xc2, (byte)0xfd, (byte)0x3b, (byte)0x2f, 
            }, new byte[] {
                (byte)0x26, (byte)0x95, (byte)0x5f, (byte)0x68, 
                (byte)0x35, (byte)0xaf, (byte)0x60, (byte)0x9a, 
            }, new byte[] {
                (byte)0x5c, (byte)0x51, (byte)0x3c, (byte)0x9c, 
                (byte)0x48, (byte)0x86, (byte)0xc0, (byte)0x88, 
            }); 
            if (CAPI.KeySizes.Contains(keySizes, 16))
            CAPI.Cipher.KnownTest(engine, PaddingMode.None, new byte[] {
                (byte)0x37, (byte)0xd0, (byte)0x6b, (byte)0xb5, 
                (byte)0x16, (byte)0xcb, (byte)0x75, (byte)0x46, 
                (byte)0x37, (byte)0xd0, (byte)0x6b, (byte)0xb5, 
                (byte)0x16, (byte)0xcb, (byte)0x75, (byte)0x46, 
            }, new byte[] {
                (byte)0x16, (byte)0x4d, (byte)0x5e, (byte)0x40, 
                (byte)0x4f, (byte)0x27, (byte)0x52, (byte)0x32, 
            }, new byte[] {
                (byte)0x0a, (byte)0x2a, (byte)0xee, (byte)0xae, 
                (byte)0x3f, (byte)0xf4, (byte)0xab, (byte)0x77, 
            }); 
            if (CAPI.KeySizes.Contains(keySizes, 24))
            CAPI.Cipher.KnownTest(engine, PaddingMode.None, new byte[] {
                (byte)0x37, (byte)0xd0, (byte)0x6b, (byte)0xb5, 
                (byte)0x16, (byte)0xcb, (byte)0x75, (byte)0x46, 
                (byte)0x37, (byte)0xd0, (byte)0x6b, (byte)0xb5, 
                (byte)0x16, (byte)0xcb, (byte)0x75, (byte)0x46, 
                (byte)0x37, (byte)0xd0, (byte)0x6b, (byte)0xb5, 
                (byte)0x16, (byte)0xcb, (byte)0x75, (byte)0x46, 
            }, new byte[] {
                (byte)0x16, (byte)0x4d, (byte)0x5e, (byte)0x40, 
                (byte)0x4f, (byte)0x27, (byte)0x52, (byte)0x32, 
            }, new byte[] {
                (byte)0x0a, (byte)0x2a, (byte)0xee, (byte)0xae, 
                (byte)0x3f, (byte)0xf4, (byte)0xab, (byte)0x77, 
            }); 
            if (CAPI.KeySizes.Contains(keySizes, 16))
            CAPI.Cipher.KnownTest(engine, PaddingMode.None, new byte[] {
                (byte)0x1f, (byte)0x08, (byte)0x26, (byte)0x0d, 
                (byte)0x1a, (byte)0xc2, (byte)0x46, (byte)0x5e, 
                (byte)0x1f, (byte)0x08, (byte)0x26, (byte)0x0d, 
                (byte)0x1a, (byte)0xc2, (byte)0x46, (byte)0x5e, 
            }, new byte[] {
                (byte)0x6b, (byte)0x05, (byte)0x6e, (byte)0x18, 
                (byte)0x75, (byte)0x9f, (byte)0x5c, (byte)0xca, 
            }, new byte[] {
                (byte)0xef, (byte)0x1b, (byte)0xf0, (byte)0x3e, 
                (byte)0x5d, (byte)0xfa, (byte)0x57, (byte)0x5a, 
            }); 
            if (CAPI.KeySizes.Contains(keySizes, 24))
            CAPI.Cipher.KnownTest(engine, PaddingMode.None, new byte[] {
                (byte)0x1f, (byte)0x08, (byte)0x26, (byte)0x0d, 
                (byte)0x1a, (byte)0xc2, (byte)0x46, (byte)0x5e, 
                (byte)0x1f, (byte)0x08, (byte)0x26, (byte)0x0d, 
                (byte)0x1a, (byte)0xc2, (byte)0x46, (byte)0x5e, 
                (byte)0x1f, (byte)0x08, (byte)0x26, (byte)0x0d, 
                (byte)0x1a, (byte)0xc2, (byte)0x46, (byte)0x5e, 
            }, new byte[] {
                (byte)0x6b, (byte)0x05, (byte)0x6e, (byte)0x18, 
                (byte)0x75, (byte)0x9f, (byte)0x5c, (byte)0xca, 
            }, new byte[] {
                (byte)0xef, (byte)0x1b, (byte)0xf0, (byte)0x3e, 
                (byte)0x5d, (byte)0xfa, (byte)0x57, (byte)0x5a, 
            }); 
            if (CAPI.KeySizes.Contains(keySizes, 16))
            CAPI.Cipher.KnownTest(engine, PaddingMode.None, new byte[] {
                (byte)0x58, (byte)0x40, (byte)0x23, (byte)0x64, 
                (byte)0x1a, (byte)0xba, (byte)0x61, (byte)0x76, 
                (byte)0x58, (byte)0x40, (byte)0x23, (byte)0x64, 
                (byte)0x1a, (byte)0xba, (byte)0x61, (byte)0x76, 
            }, new byte[] {
                (byte)0x00, (byte)0x4b, (byte)0xd6, (byte)0xef, 
                (byte)0x09, (byte)0x17, (byte)0x60, (byte)0x62, 
            }, new byte[] {
                (byte)0x88, (byte)0xbf, (byte)0x0d, (byte)0xb6, 
                (byte)0xd7, (byte)0x0d, (byte)0xee, (byte)0x56, 
            }); 
            if (CAPI.KeySizes.Contains(keySizes, 24))
            CAPI.Cipher.KnownTest(engine, PaddingMode.None, new byte[] {
                (byte)0x58, (byte)0x40, (byte)0x23, (byte)0x64, 
                (byte)0x1a, (byte)0xba, (byte)0x61, (byte)0x76, 
                (byte)0x58, (byte)0x40, (byte)0x23, (byte)0x64, 
                (byte)0x1a, (byte)0xba, (byte)0x61, (byte)0x76, 
                (byte)0x58, (byte)0x40, (byte)0x23, (byte)0x64, 
                (byte)0x1a, (byte)0xba, (byte)0x61, (byte)0x76, 
            }, new byte[] {
                (byte)0x00, (byte)0x4b, (byte)0xd6, (byte)0xef, 
                (byte)0x09, (byte)0x17, (byte)0x60, (byte)0x62, 
            }, new byte[] {
                (byte)0x88, (byte)0xbf, (byte)0x0d, (byte)0xb6, 
                (byte)0xd7, (byte)0x0d, (byte)0xee, (byte)0x56, 
            }); 
            if (CAPI.KeySizes.Contains(keySizes, 16))
            CAPI.Cipher.KnownTest(engine, PaddingMode.None, new byte[] {
                (byte)0x02, (byte)0x58, (byte)0x16, (byte)0x16, 
                (byte)0x46, (byte)0x29, (byte)0xb0, (byte)0x07, 
                (byte)0x02, (byte)0x58, (byte)0x16, (byte)0x16, 
                (byte)0x46, (byte)0x29, (byte)0xb0, (byte)0x07, 
            }, new byte[] {
                (byte)0x48, (byte)0x0d, (byte)0x39, (byte)0x00, 
                (byte)0x6e, (byte)0xe7, (byte)0x62, (byte)0xf2, 
            }, new byte[] {
                (byte)0xa1, (byte)0xf9, (byte)0x91, (byte)0x55, 
                (byte)0x41, (byte)0x02, (byte)0x0b, (byte)0x56, 
            }); 
            if (CAPI.KeySizes.Contains(keySizes, 24))
            CAPI.Cipher.KnownTest(engine, PaddingMode.None, new byte[] {
                (byte)0x02, (byte)0x58, (byte)0x16, (byte)0x16, 
                (byte)0x46, (byte)0x29, (byte)0xb0, (byte)0x07, 
                (byte)0x02, (byte)0x58, (byte)0x16, (byte)0x16, 
                (byte)0x46, (byte)0x29, (byte)0xb0, (byte)0x07, 
                (byte)0x02, (byte)0x58, (byte)0x16, (byte)0x16, 
                (byte)0x46, (byte)0x29, (byte)0xb0, (byte)0x07, 
            }, new byte[] {
                (byte)0x48, (byte)0x0d, (byte)0x39, (byte)0x00, 
                (byte)0x6e, (byte)0xe7, (byte)0x62, (byte)0xf2, 
            }, new byte[] {
                (byte)0xa1, (byte)0xf9, (byte)0x91, (byte)0x55, 
                (byte)0x41, (byte)0x02, (byte)0x0b, (byte)0x56, 
            }); 
            if (CAPI.KeySizes.Contains(keySizes, 16))
            CAPI.Cipher.KnownTest(engine, PaddingMode.None, new byte[] {
                (byte)0x49, (byte)0x79, (byte)0x3e, (byte)0xbc, 
                (byte)0x79, (byte)0xb3, (byte)0x25, (byte)0x8f, 
                (byte)0x49, (byte)0x79, (byte)0x3e, (byte)0xbc, 
                (byte)0x79, (byte)0xb3, (byte)0x25, (byte)0x8f, 
            }, new byte[] {
                (byte)0x43, (byte)0x75, (byte)0x40, (byte)0xc8, 
                (byte)0x69, (byte)0x8f, (byte)0x3c, (byte)0xfa, 
            }, new byte[] {
                (byte)0x6f, (byte)0xbf, (byte)0x1c, (byte)0xaf, 
                (byte)0xcf, (byte)0xfd, (byte)0x05, (byte)0x56, 
            }); 
            if (CAPI.KeySizes.Contains(keySizes, 24))
            CAPI.Cipher.KnownTest(engine, PaddingMode.None, new byte[] {
                (byte)0x49, (byte)0x79, (byte)0x3e, (byte)0xbc, 
                (byte)0x79, (byte)0xb3, (byte)0x25, (byte)0x8f, 
                (byte)0x49, (byte)0x79, (byte)0x3e, (byte)0xbc, 
                (byte)0x79, (byte)0xb3, (byte)0x25, (byte)0x8f, 
                (byte)0x49, (byte)0x79, (byte)0x3e, (byte)0xbc, 
                (byte)0x79, (byte)0xb3, (byte)0x25, (byte)0x8f, 
            }, new byte[] {
                (byte)0x43, (byte)0x75, (byte)0x40, (byte)0xc8, 
                (byte)0x69, (byte)0x8f, (byte)0x3c, (byte)0xfa, 
            }, new byte[] {
                (byte)0x6f, (byte)0xbf, (byte)0x1c, (byte)0xaf, 
                (byte)0xcf, (byte)0xfd, (byte)0x05, (byte)0x56, 
            }); 
            if (CAPI.KeySizes.Contains(keySizes, 16))
            CAPI.Cipher.KnownTest(engine, PaddingMode.None, new byte[] {
                (byte)0x4f, (byte)0xb0, (byte)0x5e, (byte)0x15, 
                (byte)0x15, (byte)0xab, (byte)0x73, (byte)0xa7, 
                (byte)0x4f, (byte)0xb0, (byte)0x5e, (byte)0x15, 
                (byte)0x15, (byte)0xab, (byte)0x73, (byte)0xa7, 
            }, new byte[] {
                (byte)0x07, (byte)0x2d, (byte)0x43, (byte)0xa0, 
                (byte)0x77, (byte)0x07, (byte)0x52, (byte)0x92, 
            }, new byte[] {
                (byte)0x2f, (byte)0x22, (byte)0xe4, (byte)0x9b, 
                (byte)0xab, (byte)0x7c, (byte)0xa1, (byte)0xac, 
            }); 
            if (CAPI.KeySizes.Contains(keySizes, 24))
            CAPI.Cipher.KnownTest(engine, PaddingMode.None, new byte[] {
                (byte)0x4f, (byte)0xb0, (byte)0x5e, (byte)0x15, 
                (byte)0x15, (byte)0xab, (byte)0x73, (byte)0xa7, 
                (byte)0x4f, (byte)0xb0, (byte)0x5e, (byte)0x15, 
                (byte)0x15, (byte)0xab, (byte)0x73, (byte)0xa7, 
                (byte)0x4f, (byte)0xb0, (byte)0x5e, (byte)0x15, 
                (byte)0x15, (byte)0xab, (byte)0x73, (byte)0xa7, 
            }, new byte[] {
                (byte)0x07, (byte)0x2d, (byte)0x43, (byte)0xa0, 
                (byte)0x77, (byte)0x07, (byte)0x52, (byte)0x92, 
            }, new byte[] {
                (byte)0x2f, (byte)0x22, (byte)0xe4, (byte)0x9b, 
                (byte)0xab, (byte)0x7c, (byte)0xa1, (byte)0xac, 
            }); 
            if (CAPI.KeySizes.Contains(keySizes, 16))
            CAPI.Cipher.KnownTest(engine, PaddingMode.None, new byte[] {
                (byte)0x49, (byte)0xe9, (byte)0x5d, (byte)0x6d, 
                (byte)0x4c, (byte)0xa2, (byte)0x29, (byte)0xbf, 
                (byte)0x49, (byte)0xe9, (byte)0x5d, (byte)0x6d, 
                (byte)0x4c, (byte)0xa2, (byte)0x29, (byte)0xbf, 
            }, new byte[] {
                (byte)0x02, (byte)0xfe, (byte)0x55, (byte)0x77, 
                (byte)0x81, (byte)0x17, (byte)0xf1, (byte)0x2a, 
            }, new byte[] {
                (byte)0x5a, (byte)0x6b, (byte)0x61, (byte)0x2c, 
                (byte)0xc2, (byte)0x6c, (byte)0xce, (byte)0x4a, 
            }); 
            if (CAPI.KeySizes.Contains(keySizes, 24))
            CAPI.Cipher.KnownTest(engine, PaddingMode.None, new byte[] {
                (byte)0x49, (byte)0xe9, (byte)0x5d, (byte)0x6d, 
                (byte)0x4c, (byte)0xa2, (byte)0x29, (byte)0xbf, 
                (byte)0x49, (byte)0xe9, (byte)0x5d, (byte)0x6d, 
                (byte)0x4c, (byte)0xa2, (byte)0x29, (byte)0xbf, 
                (byte)0x49, (byte)0xe9, (byte)0x5d, (byte)0x6d, 
                (byte)0x4c, (byte)0xa2, (byte)0x29, (byte)0xbf, 
            }, new byte[] {
                (byte)0x02, (byte)0xfe, (byte)0x55, (byte)0x77, 
                (byte)0x81, (byte)0x17, (byte)0xf1, (byte)0x2a, 
            }, new byte[] {
                (byte)0x5a, (byte)0x6b, (byte)0x61, (byte)0x2c, 
                (byte)0xc2, (byte)0x6c, (byte)0xce, (byte)0x4a, 
            }); 
            if (CAPI.KeySizes.Contains(keySizes, 16))
            CAPI.Cipher.KnownTest(engine, PaddingMode.None, new byte[] {
                (byte)0x01, (byte)0x83, (byte)0x10, (byte)0xdc, 
                (byte)0x40, (byte)0x9b, (byte)0x26, (byte)0xd6, 
                (byte)0x01, (byte)0x83, (byte)0x10, (byte)0xdc, 
                (byte)0x40, (byte)0x9b, (byte)0x26, (byte)0xd6, 
            }, new byte[] {
                (byte)0x1d, (byte)0x9d, (byte)0x5c, (byte)0x50, 
                (byte)0x18, (byte)0xf7, (byte)0x28, (byte)0xc2, 
            }, new byte[] {
                (byte)0x5f, (byte)0x4c, (byte)0x03, (byte)0x8e, 
                (byte)0xd1, (byte)0x2b, (byte)0x2e, (byte)0x41, 
            }); 
            if (CAPI.KeySizes.Contains(keySizes, 24))
            CAPI.Cipher.KnownTest(engine, PaddingMode.None, new byte[] {
                (byte)0x01, (byte)0x83, (byte)0x10, (byte)0xdc, 
                (byte)0x40, (byte)0x9b, (byte)0x26, (byte)0xd6, 
                (byte)0x01, (byte)0x83, (byte)0x10, (byte)0xdc, 
                (byte)0x40, (byte)0x9b, (byte)0x26, (byte)0xd6, 
                (byte)0x01, (byte)0x83, (byte)0x10, (byte)0xdc, 
                (byte)0x40, (byte)0x9b, (byte)0x26, (byte)0xd6, 
            }, new byte[] {
                (byte)0x1d, (byte)0x9d, (byte)0x5c, (byte)0x50, 
                (byte)0x18, (byte)0xf7, (byte)0x28, (byte)0xc2, 
            }, new byte[] {
                (byte)0x5f, (byte)0x4c, (byte)0x03, (byte)0x8e, 
                (byte)0xd1, (byte)0x2b, (byte)0x2e, (byte)0x41, 
            }); 
            if (CAPI.KeySizes.Contains(keySizes, 16))
            CAPI.Cipher.KnownTest(engine, PaddingMode.None, new byte[] {
                (byte)0x1c, (byte)0x58, (byte)0x7f, (byte)0x1c, 
                (byte)0x13, (byte)0x92, (byte)0x4f, (byte)0xef, 
                (byte)0x1c, (byte)0x58, (byte)0x7f, (byte)0x1c, 
                (byte)0x13, (byte)0x92, (byte)0x4f, (byte)0xef, 
            }, new byte[] {
                (byte)0x30, (byte)0x55, (byte)0x32, (byte)0x28, 
                (byte)0x6d, (byte)0x6f, (byte)0x29, (byte)0x5a, 
            }, new byte[] {
                (byte)0x63, (byte)0xfa, (byte)0xc0, (byte)0xd0, 
                (byte)0x34, (byte)0xd9, (byte)0xf7, (byte)0x93, 
            }); 
            if (CAPI.KeySizes.Contains(keySizes, 24))
            CAPI.Cipher.KnownTest(engine, PaddingMode.None, new byte[] {
                (byte)0x1c, (byte)0x58, (byte)0x7f, (byte)0x1c, 
                (byte)0x13, (byte)0x92, (byte)0x4f, (byte)0xef, 
                (byte)0x1c, (byte)0x58, (byte)0x7f, (byte)0x1c, 
                (byte)0x13, (byte)0x92, (byte)0x4f, (byte)0xef, 
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
        public static void TestSMIME(IBlockCipher tdes)
        {
            // указать синхропосылку
            byte[] iv = new byte[] { 
                (byte)0xBA, (byte)0xF1, (byte)0xCA, (byte)0x79, 
                (byte)0x31, (byte)0x21, (byte)0x3C, (byte)0x4E        
            }; 
            // создать алгоритм
            using (KeyWrap algorithm = new CAPI.ANSI.Wrap.SMIME(tdes, 24, iv))
            {
                // создать генератор случайных данных
                using (IRand rand = new CAPI.Rnd.Fixed(new byte[] {
                    (byte)0xFA, (byte)0x06, (byte)0x0A, (byte)0x45
                })){
                    // выполнить тест
                    KeyWrap.KnownTest(rand, algorithm, new byte[] {
                        (byte)0x6A, (byte)0x89, (byte)0x70, (byte)0xBF, 
                        (byte)0x68, (byte)0xC9, (byte)0x2C, (byte)0xAE, 
                        (byte)0xA8, (byte)0x4A, (byte)0x8D, (byte)0xF2, 
                        (byte)0x85, (byte)0x10, (byte)0x85, (byte)0x86, 
                        (byte)0x07, (byte)0x12, (byte)0x63, (byte)0x80, 
                        (byte)0xCC, (byte)0x47, (byte)0xAB, (byte)0x2D
                    }, new byte[] {
                        (byte)0x8C, (byte)0x63, (byte)0x7D, (byte)0x88, 
                        (byte)0x72, (byte)0x23, (byte)0xA2, (byte)0xF9, 
                        (byte)0x65, (byte)0xB5, (byte)0x66, (byte)0xEB, 
                        (byte)0x01, (byte)0x4B, (byte)0x0F, (byte)0xA5, 
                        (byte)0xD5, (byte)0x23, (byte)0x00, (byte)0xA3, 
                        (byte)0xF7, (byte)0xEA, (byte)0x40, (byte)0xFF, 
                        (byte)0xFC, (byte)0x57, (byte)0x72, (byte)0x03, 
                        (byte)0xC7, (byte)0x1B, (byte)0xAF, (byte)0x3B        
                    }, new byte[] {
                        (byte)0xC0, (byte)0x3C, (byte)0x51, (byte)0x4A, 
                        (byte)0xBD, (byte)0xB9, (byte)0xE2, (byte)0xC5, 
                        (byte)0xAA, (byte)0xC0, (byte)0x38, (byte)0x57, 
                        (byte)0x2B, (byte)0x5E, (byte)0x24, (byte)0x55, 
                        (byte)0x38, (byte)0x76, (byte)0xB3, (byte)0x77, 
                        (byte)0xAA, (byte)0xFB, (byte)0x82, (byte)0xEC, 
                        (byte)0xA5, (byte)0xA9, (byte)0xD7, (byte)0x3F, 
                        (byte)0x8A, (byte)0xB1, (byte)0x43, (byte)0xD9, 
                        (byte)0xEC, (byte)0x74, (byte)0xE6, (byte)0xCA, 
                        (byte)0xD7, (byte)0xDB, (byte)0x26, (byte)0x0C            
                    }); 
                }
            }
        }
    }
}