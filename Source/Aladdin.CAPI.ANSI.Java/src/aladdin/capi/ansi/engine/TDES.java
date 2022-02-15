package aladdin.capi.ansi.engine;
import aladdin.*; 
import aladdin.capi.*; 
import java.security.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Алгоритм шифрования TDES
///////////////////////////////////////////////////////////////////////////
public final class TDES extends Cipher
{
    // преобразование DES и допустимые размеры ключей
    private final Cipher des; private final int[] keySizes;
        
	// конструктор
	public TDES(Cipher des, int[] keySizes) 
    { 
        // сохранить переданные параметры
        this.des = RefObject.addRef(des); this.keySizes = keySizes; 
    } 
    // освободить ресурсы 
    @Override protected void onClose() throws IOException 
    {
        // освободить ресурсы 
        RefObject.release(des); super.onClose();
    }
    // тип ключа
    @Override public final SecretKeyFactory keyFactory() 
    { 
        // тип ключа
        return aladdin.capi.ansi.keys.TDES.INSTANCE; 
    } 
	// размер ключей
	@Override public final int[] keySizes() { return keySizes; }
        
    // размер блока
	@Override public final int blockSize() { return des.blockSize(); }

	// алгоритм зашифрования блока данных
	@Override protected final Transform createEncryption(ISecretKey key) 
        throws IOException, InvalidKeyException
	{
        // проверить тип ключа
        if (key.value() == null) throw new InvalidKeyException();

        // проверить размер ключа
        if (!KeySizes.contains(keySizes, key.length())) 
        {
            // при ошибке выбросить исключение
            throw new InvalidKeyException();
        }
        // вернуть алгоритм зашифрования блока данных
        return new Encryption(des, key); 
	}
	// алгоритм расшифрования блока данных
	@Override protected final Transform createDecryption(ISecretKey key) 
        throws IOException, InvalidKeyException
	{
        // проверить тип ключа
        if (key.value() == null) throw new InvalidKeyException();

        // проверить размер ключа
        if (!KeySizes.contains(keySizes, key.length())) 
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
	public static class Encryption extends BlockTransform
	{
		// используемые преобразования
		private final Transform[] transforms; 

		// Конструктор
		public Encryption(Cipher des, ISecretKey key) throws IOException, InvalidKeyException
		{ 
			// проверить тип ключа
			super(8); byte[] value = key.value(); if (value == null) 
            {
                // при ошибке выбросить исключение
                throw new InvalidKeyException();
            }
            // проверить размер ключа
            if (value.length != 16 && value.length != 24)
            {
                // при ошибке выбросить исключение
                throw new InvalidKeyException();
            }
            // сохранить переданные параметры
            transforms = new Transform[3]; switch (value.length)
            {
            case 16:
            {
                // извлечь используемые ключи
                byte[] key1 = new byte[8]; System.arraycopy(value, 0, key1, 0, 8); 
                byte[] key2 = new byte[8]; System.arraycopy(value, 8, key2, 0, 8);
                
                // указать используемые преобразования
                try (ISecretKey k1 = des.keyFactory().create(key1)) 
                { 
                    transforms[0] = des.createEncryption(k1, PaddingMode.NONE); 
                    transforms[0].init();
                }
                // обработать неожидаемую ошибку
                catch (InvalidKeyException e) { throw new IOException(e); }
                
                try (ISecretKey k2 = des.keyFactory().create(key2)) 
                { 
                    transforms[1] = des.createDecryption(k2, PaddingMode.NONE); 
                    transforms[1].init();
                }
                // обработать неожидаемую ошибку
                catch (InvalidKeyException e) { throw new IOException(e); }
                
                // указать используемые преобразования
                transforms[2] = RefObject.addRef(transforms[0]); break; 
            }
            case 24:
            {
                // извлечь используемые ключи
                byte[] key1 = new byte[8]; System.arraycopy(value,  0, key1, 0, 8); 
                byte[] key2 = new byte[8]; System.arraycopy(value,  8, key2, 0, 8);
                byte[] key3 = new byte[8]; System.arraycopy(value, 16, key3, 0, 8);
                
                // указать используемые преобразования
                try (ISecretKey k1 = des.keyFactory().create(key1)) 
                { 
                    transforms[0] = des.createEncryption(k1, PaddingMode.NONE); 
                    transforms[0].init();
                }
                // обработать неожидаемую ошибку
                catch (InvalidKeyException e) { throw new IOException(e); }
                
                try (ISecretKey k2 = des.keyFactory().create(key2)) 
                { 
                    transforms[1] = des.createDecryption(k2, PaddingMode.NONE);
                    transforms[1].init();
                }
                // обработать неожидаемую ошибку
                catch (InvalidKeyException e) { throw new IOException(e); }
                
                try (ISecretKey k3 = des.keyFactory().create(key3)) 
                { 
                    transforms[2] = des.createEncryption(k3, PaddingMode.NONE); 
                    transforms[2].init();
                } 
                // обработать неожидаемую ошибку
                catch (InvalidKeyException e) { throw new IOException(e); } break; 
            }}
            
		}
        // освободить ресурсы 
        @Override protected void onClose() throws IOException 
        { 
            // освободить ресурсы 
            RefObject.release(transforms[2]); RefObject.release(transforms[1]); 
            
            // освободить ресурсы 
            RefObject.release(transforms[0]); super.onClose();            
        }
		///////////////////////////////////////////////////////////////////////
		// Обработка одного блока данных
		///////////////////////////////////////////////////////////////////////
		@Override protected void update(byte[] src, 
            int srcOff, byte[] dest, int destOff) throws IOException
		{
            transforms[0].update(src , srcOff , 8, dest, destOff); 
            transforms[1].update(dest, destOff, 8, dest, destOff); 
            transforms[2].update(dest, destOff, 8, dest, destOff); 
        }
	}
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм расшифрования блока
	///////////////////////////////////////////////////////////////////////////
	public static class Decryption extends BlockTransform
	{
		// используемые преобразования
		private final Transform[] transforms; 

		// Конструктор
		public Decryption(Cipher des, ISecretKey key) throws IOException, InvalidKeyException
		{ 
			// проверить тип ключа
			super(8); byte[] value = key.value(); if (value == null) 
            {
                // при ошибке выбросить исключение
                throw new InvalidKeyException();
            }
            // проверить размер ключа
            if (value.length != 16 && value.length != 24)
            {
                // при ошибке выбросить исключение
                throw new InvalidKeyException();
            }
            // сохранить переданные параметры
            transforms = new Transform[3]; switch (value.length)
            {
            case 16:
            {
                // извлечь используемые ключи
                byte[] key1 = new byte[8]; System.arraycopy(value, 0, key1, 0, 8); 
                byte[] key2 = new byte[8]; System.arraycopy(value, 8, key2, 0, 8);
                
                // указать используемые преобразования
                try (ISecretKey k1 = des.keyFactory().create(key1)) 
                { 
                    transforms[0] = des.createDecryption(k1, PaddingMode.NONE); 
                    transforms[0].init();
                }
                // обработать неожидаемую ошибку
                catch (InvalidKeyException e) { throw new IOException(e); }
                
                try (ISecretKey k2 = des.keyFactory().create(key2)) 
                { 
                    transforms[1] = des.createEncryption(k2, PaddingMode.NONE); 
                    transforms[1].init();
                }
                // обработать неожидаемую ошибку
                catch (InvalidKeyException e) { throw new IOException(e); }
                
                // указать используемые преобразования
                transforms[2] = RefObject.addRef(transforms[0]); break; 
            }
            case 24:
            {
                // извлечь используемые ключи
                byte[] key1 = new byte[8]; System.arraycopy(value,  0, key1, 0, 8); 
                byte[] key2 = new byte[8]; System.arraycopy(value,  8, key2, 0, 8);
                byte[] key3 = new byte[8]; System.arraycopy(value, 16, key3, 0, 8);
                
                // указать используемые преобразования
                try (ISecretKey k3 = des.keyFactory().create(key3)) 
                { 
                    transforms[0] = des.createDecryption(k3, PaddingMode.NONE); 
                    transforms[0].init();
                } 
                // обработать неожидаемую ошибку
                catch (InvalidKeyException e) { throw new IOException(e); }
                
                try (ISecretKey k2 = des.keyFactory().create(key2)) 
                { 
                    transforms[1] = des.createEncryption(k2, PaddingMode.NONE); 
                    transforms[1].init();
                }
                // обработать неожидаемую ошибку
                catch (InvalidKeyException e) { throw new IOException(e); }
                
                try (ISecretKey k1 = des.keyFactory().create(key1)) 
                { 
                    transforms[2] = des.createDecryption(k1, PaddingMode.NONE); 
                    transforms[2].init();
                } 
                // обработать неожидаемую ошибку
                catch (InvalidKeyException e) { throw new IOException(e); }
            }}
            
		}
        // освободить ресурсы 
        @Override protected void onClose() throws IOException 
        { 
            // освободить ресурсы 
            RefObject.release(transforms[2]); RefObject.release(transforms[1]); 
            
            // освободить ресурсы 
            RefObject.release(transforms[0]); super.onClose();            
        }
		///////////////////////////////////////////////////////////////////////
		// Обработка одного блока данных
		///////////////////////////////////////////////////////////////////////
		@Override protected void update(byte[] src, 
            int srcOff, byte[] dest, int destOff) throws IOException
		{
            transforms[0].update(src , srcOff , 8, dest, destOff); 
            transforms[1].update(dest, destOff, 8, dest, destOff); 
            transforms[2].update(dest, destOff, 8, dest, destOff); 
		}
	}
    ////////////////////////////////////////////////////////////////////////////
    // Тесты известного ответа
    ////////////////////////////////////////////////////////////////////////////
    public static void test(Cipher engine) throws Exception
    {
        if (KeySizes.contains(engine.keySizes(), 16))
        Cipher.knownTest(engine, PaddingMode.NONE, new byte[] {
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
        if (KeySizes.contains(engine.keySizes(), 24))
        Cipher.knownTest(engine, PaddingMode.NONE, new byte[] {
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
        if (KeySizes.contains(engine.keySizes(), 16))
        Cipher.knownTest(engine, PaddingMode.NONE, new byte[] {
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
        if (KeySizes.contains(engine.keySizes(), 24))
        Cipher.knownTest(engine, PaddingMode.NONE, new byte[] {
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
        if (KeySizes.contains(engine.keySizes(), 16))
        Cipher.knownTest(engine, PaddingMode.NONE, new byte[] {
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
        if (KeySizes.contains(engine.keySizes(), 24))
        Cipher.knownTest(engine, PaddingMode.NONE, new byte[] {
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
        if (KeySizes.contains(engine.keySizes(), 16))
        Cipher.knownTest(engine, PaddingMode.NONE, new byte[] {
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
        if (KeySizes.contains(engine.keySizes(), 24))
        Cipher.knownTest(engine, PaddingMode.NONE, new byte[] {
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
        if (KeySizes.contains(engine.keySizes(), 16))
        Cipher.knownTest(engine, PaddingMode.NONE, new byte[] {
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
        if (KeySizes.contains(engine.keySizes(), 24))
        Cipher.knownTest(engine, PaddingMode.NONE, new byte[] {
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
        if (KeySizes.contains(engine.keySizes(), 16))
        Cipher.knownTest(engine, PaddingMode.NONE, new byte[] {
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
        if (KeySizes.contains(engine.keySizes(), 24))
        Cipher.knownTest(engine, PaddingMode.NONE, new byte[] {
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
        if (KeySizes.contains(engine.keySizes(), 16))
        Cipher.knownTest(engine, PaddingMode.NONE, new byte[] {
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
        if (KeySizes.contains(engine.keySizes(), 24))
        Cipher.knownTest(engine, PaddingMode.NONE, new byte[] {
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
        if (KeySizes.contains(engine.keySizes(), 16))
        Cipher.knownTest(engine, PaddingMode.NONE, new byte[] {
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
        if (KeySizes.contains(engine.keySizes(), 24))
        Cipher.knownTest(engine, PaddingMode.NONE, new byte[] {
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
        if (KeySizes.contains(engine.keySizes(), 16))
        Cipher.knownTest(engine, PaddingMode.NONE, new byte[] {
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
        if (KeySizes.contains(engine.keySizes(), 24))
        Cipher.knownTest(engine, PaddingMode.NONE, new byte[] {
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
        if (KeySizes.contains(engine.keySizes(), 16))
        Cipher.knownTest(engine, PaddingMode.NONE, new byte[] {
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
        if (KeySizes.contains(engine.keySizes(), 24))
        Cipher.knownTest(engine, PaddingMode.NONE, new byte[] {
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
        if (KeySizes.contains(engine.keySizes(), 16))
        Cipher.knownTest(engine, PaddingMode.NONE, new byte[] {
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
        if (KeySizes.contains(engine.keySizes(), 24))
        Cipher.knownTest(engine, PaddingMode.NONE, new byte[] {
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
        if (KeySizes.contains(engine.keySizes(), 16))
        Cipher.knownTest(engine, PaddingMode.NONE, new byte[] {
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
        if (KeySizes.contains(engine.keySizes(), 24))
        Cipher.knownTest(engine, PaddingMode.NONE, new byte[] {
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
        if (KeySizes.contains(engine.keySizes(), 16))
        Cipher.knownTest(engine, PaddingMode.NONE, new byte[] {
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
        if (KeySizes.contains(engine.keySizes(), 24))
        Cipher.knownTest(engine, PaddingMode.NONE, new byte[] {
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
        if (KeySizes.contains(engine.keySizes(), 16))
        Cipher.knownTest(engine, PaddingMode.NONE, new byte[] {
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
        if (KeySizes.contains(engine.keySizes(), 24))
        Cipher.knownTest(engine, PaddingMode.NONE, new byte[] {
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
        if (KeySizes.contains(engine.keySizes(), 16))
        Cipher.knownTest(engine, PaddingMode.NONE, new byte[] {
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
        if (KeySizes.contains(engine.keySizes(), 24))
        Cipher.knownTest(engine, PaddingMode.NONE, new byte[] {
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
        if (KeySizes.contains(engine.keySizes(), 16))
        Cipher.knownTest(engine, PaddingMode.NONE, new byte[] {
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
        if (KeySizes.contains(engine.keySizes(), 24))
        Cipher.knownTest(engine, PaddingMode.NONE, new byte[] {
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
        if (KeySizes.contains(engine.keySizes(), 16))
        Cipher.knownTest(engine, PaddingMode.NONE, new byte[] {
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
        if (KeySizes.contains(engine.keySizes(), 24))
        Cipher.knownTest(engine, PaddingMode.NONE, new byte[] {
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
        if (KeySizes.contains(engine.keySizes(), 16))
        Cipher.knownTest(engine, PaddingMode.NONE, new byte[] {
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
        if (KeySizes.contains(engine.keySizes(), 24))
        Cipher.knownTest(engine, PaddingMode.NONE, new byte[] {
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
        if (KeySizes.contains(engine.keySizes(), 16))
        Cipher.knownTest(engine, PaddingMode.NONE, new byte[] {
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
        if (KeySizes.contains(engine.keySizes(), 24))
        Cipher.knownTest(engine, PaddingMode.NONE, new byte[] {
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
    public static void testSMIME(IBlockCipher tdes) throws Exception
    {
        // указать синхропосылку
        byte[] iv = new byte[] { 
            (byte)0xBA, (byte)0xF1, (byte)0xCA, (byte)0x79, 
            (byte)0x31, (byte)0x21, (byte)0x3C, (byte)0x4E        
        }; 
        // создать алгоритм
        try (KeyWrap algorithm = new aladdin.capi.ansi.wrap.SMIME(tdes, iv))
        {
            // создать генератор случайных данных
            try (Test.Rand rand = new Test.Rand(new byte[] {
                (byte)0xFA, (byte)0x06, (byte)0x0A, (byte)0x45
            })){
                // выполнить тест
                KeyWrap.knownTest(rand, algorithm, new byte[] {
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
