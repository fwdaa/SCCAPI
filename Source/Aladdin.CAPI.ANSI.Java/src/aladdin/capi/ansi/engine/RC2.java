package aladdin.capi.ansi.engine;
import aladdin.math.*;
import aladdin.capi.*; 
import java.security.*; 

///////////////////////////////////////////////////////////////////////////
// Алгоритм шифрования RC2
///////////////////////////////////////////////////////////////////////////
public final class RC2 extends Cipher
{
    // способ кодирования чисел
    private static final Endian ENDIAN = Endian.LITTLE_ENDIAN; 
    
    // эффективное число битов и допустимые размеры ключей
    private final int effectiveKeyBits; private final int[] keySizes;
        
    // конструктор
    public RC2(int effectiveKeyBits) { this(effectiveKeyBits, KeySizes.range(1, 128)); }
    // конструктор
    public RC2(int effectiveKeyBits, int[] keySizes) 
    {  
        // сохранить переданные параметры
        this.effectiveKeyBits = effectiveKeyBits; this.keySizes = keySizes; 
    } 
    // тип ключа
    @Override public final SecretKeyFactory keyFactory() 
    { 
        // тип ключа
        return new aladdin.capi.ansi.keys.RC2(keySizes); 
    } 
    // размер блока
	@Override public final int blockSize() { return 8;	}

	// алгоритм зашифрования блока данных
	@Override protected final Transform createEncryption(ISecretKey key) 
        throws InvalidKeyException 
	{
		// проверить тип ключа
		byte[] value = key.value(); if (value == null)
		{
			// при ошибке выбросить исключение
			throw new InvalidKeyException();
		}
        // проверить размер ключа
        if (!KeySizes.contains(keyFactory().keySizes(), value.length))
        {
            // при ошибке выбросить исключение
            throw new InvalidKeyException(); 
        }
        // вернуть алгоритм зашифрования блока данных
		return new Encryption(key, effectiveKeyBits); 
	}
	// алгоритм расшифрования блока данных
	@Override protected final Transform createDecryption(ISecretKey key) 
        throws InvalidKeyException 
	{
		// проверить тип ключа
		byte[] value = key.value(); if (value == null)
		{
			// при ошибке выбросить исключение
			throw new InvalidKeyException();
		}
        // проверить размер ключа
        if (!KeySizes.contains(keyFactory().keySizes(), value.length))
        {
            // при ошибке выбросить исключение
            throw new InvalidKeyException(); 
        }
        // вернуть алгоритм расшифрования блока данных
		return new Decryption(key, effectiveKeyBits);
	}
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм зашифрования блока
	///////////////////////////////////////////////////////////////////////////
	public static class Encryption extends BlockTransform
	{
		// расписание ключей
		private final int[] keys; 

		// Конструктор
		public Encryption(ISecretKey key, int effectiveKeyBits) throws InvalidKeyException 
		{ 
			// сохранить переданные параметры
			super(8); if (key.value() == null) throw new InvalidKeyException();
            
            // создать расписание ключей
            keys = getKeys(key.value(), effectiveKeyBits); 
        }
		///////////////////////////////////////////////////////////////////////
		// Обработка одного блока данных
		///////////////////////////////////////////////////////////////////////
		@Override protected void update(byte[] src, int srcOff, byte[] dest, int destOff)
		{
            int x76 = Convert.toInt16(src, srcOff + 6, ENDIAN) & 0xFFFF; 
            int x54 = Convert.toInt16(src, srcOff + 4, ENDIAN) & 0xFFFF; 
            int x32 = Convert.toInt16(src, srcOff + 2, ENDIAN) & 0xFFFF; 
            int x10 = Convert.toInt16(src, srcOff + 0, ENDIAN) & 0xFFFF; 

            for (int i = 0; i <= 16; i += 4)
            {
                x10 = rotateWordLeft(x10 + (x32 & ~x76) + (x54 & x76) + keys[i  ], 1);
                x32 = rotateWordLeft(x32 + (x54 & ~x10) + (x76 & x10) + keys[i+1], 2);
                x54 = rotateWordLeft(x54 + (x76 & ~x32) + (x10 & x32) + keys[i+2], 3);
                x76 = rotateWordLeft(x76 + (x10 & ~x54) + (x32 & x54) + keys[i+3], 5);
            }
            x10 += keys[x76 & 63]; x32 += keys[x10 & 63];
            x54 += keys[x32 & 63]; x76 += keys[x54 & 63];

            for (int i = 20; i <= 40; i += 4)
            {
                x10 = rotateWordLeft(x10 + (x32 & ~x76) + (x54 & x76) + keys[i  ], 1);
                x32 = rotateWordLeft(x32 + (x54 & ~x10) + (x76 & x10) + keys[i+1], 2);
                x54 = rotateWordLeft(x54 + (x76 & ~x32) + (x10 & x32) + keys[i+2], 3);
                x76 = rotateWordLeft(x76 + (x10 & ~x54) + (x32 & x54) + keys[i+3], 5);
            }
            x10 += keys[x76 & 63]; x32 += keys[x10 & 63];
            x54 += keys[x32 & 63]; x76 += keys[x54 & 63];

            for (int i = 44; i < 64; i += 4)
            {
                x10 = rotateWordLeft(x10 + (x32 & ~x76) + (x54 & x76) + keys[i  ], 1);
                x32 = rotateWordLeft(x32 + (x54 & ~x10) + (x76 & x10) + keys[i+1], 2);
                x54 = rotateWordLeft(x54 + (x76 & ~x32) + (x10 & x32) + keys[i+2], 3);
                x76 = rotateWordLeft(x76 + (x10 & ~x54) + (x32 & x54) + keys[i+3], 5);
            }
            Convert.fromInt16((short)x10, ENDIAN, dest, destOff + 0); 
            Convert.fromInt16((short)x32, ENDIAN, dest, destOff + 2); 
            Convert.fromInt16((short)x54, ENDIAN, dest, destOff + 4); 
            Convert.fromInt16((short)x76, ENDIAN, dest, destOff + 6); 
        }
	}
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм расшифрования блока
	///////////////////////////////////////////////////////////////////////////
	public static class Decryption extends BlockTransform
	{
		// расписание ключей
		private final int[] keys; 

		// Конструктор
		public Decryption(ISecretKey key, int effectiveKeyBits) throws InvalidKeyException
		{ 
			// сохранить переданные параметры
			super(8); if (key.value() == null) throw new InvalidKeyException();
            
            // создать расписание ключей
            keys = getKeys(key.value(), effectiveKeyBits); 
		}
		///////////////////////////////////////////////////////////////////////
		// Обработка одного блока данных
		///////////////////////////////////////////////////////////////////////
		@Override protected void update(byte[] src, int srcOff, byte[] dest, int destOff)
		{
            int x76 = Convert.toInt16(src, srcOff + 6, ENDIAN) & 0xFFFF; 
            int x54 = Convert.toInt16(src, srcOff + 4, ENDIAN) & 0xFFFF; 
            int x32 = Convert.toInt16(src, srcOff + 2, ENDIAN) & 0xFFFF; 
            int x10 = Convert.toInt16(src, srcOff + 0, ENDIAN) & 0xFFFF; 

            for (int i = 60; i >= 44; i -= 4)
            {
                x76 = rotateWordLeft(x76, 11) - ((x10 & ~x54) + (x32 & x54) + keys[i+3]);
                x54 = rotateWordLeft(x54, 13) - ((x76 & ~x32) + (x10 & x32) + keys[i+2]);
                x32 = rotateWordLeft(x32, 14) - ((x54 & ~x10) + (x76 & x10) + keys[i+1]);
                x10 = rotateWordLeft(x10, 15) - ((x32 & ~x76) + (x54 & x76) + keys[i  ]);
            }
            x76 -= keys[x54 & 63]; x54 -= keys[x32 & 63];
            x32 -= keys[x10 & 63]; x10 -= keys[x76 & 63];

            for (int i = 40; i >= 20; i -= 4)
            {
                x76 = rotateWordLeft(x76, 11) - ((x10 & ~x54) + (x32 & x54) + keys[i+3]);
                x54 = rotateWordLeft(x54, 13) - ((x76 & ~x32) + (x10 & x32) + keys[i+2]);
                x32 = rotateWordLeft(x32, 14) - ((x54 & ~x10) + (x76 & x10) + keys[i+1]);
                x10 = rotateWordLeft(x10, 15) - ((x32 & ~x76) + (x54 & x76) + keys[i  ]);
            }
            x76 -= keys[x54 & 63]; x54 -= keys[x32 & 63];
            x32 -= keys[x10 & 63]; x10 -= keys[x76 & 63];

            for (int i = 16; i >= 0; i -= 4)
            {
                x76 = rotateWordLeft(x76, 11) - ((x10 & ~x54) + (x32 & x54) + keys[i+3]);
                x54 = rotateWordLeft(x54, 13) - ((x76 & ~x32) + (x10 & x32) + keys[i+2]);
                x32 = rotateWordLeft(x32, 14) - ((x54 & ~x10) + (x76 & x10) + keys[i+1]);
                x10 = rotateWordLeft(x10, 15) - ((x32 & ~x76) + (x54 & x76) + keys[i  ]);
            }
            Convert.fromInt16((short)x10, ENDIAN, dest, destOff + 0); 
            Convert.fromInt16((short)x32, ENDIAN, dest, destOff + 2); 
            Convert.fromInt16((short)x54, ENDIAN, dest, destOff + 4); 
            Convert.fromInt16((short)x76, ENDIAN, dest, destOff + 6); 
		}
	}
	///////////////////////////////////////////////////////////////////////////
	// Вспомогательные таблицы
	///////////////////////////////////////////////////////////////////////////
    //
    // the values we use for key expansion (based on the digits of PI)
    //
    private static final byte[] piTable =
    {
        (byte)0xd9, (byte)0x78, (byte)0xf9, (byte)0xc4, 
        (byte)0x19, (byte)0xdd, (byte)0xb5, (byte)0xed, 
        (byte)0x28, (byte)0xe9, (byte)0xfd, (byte)0x79, 
        (byte)0x4a, (byte)0xa0, (byte)0xd8, (byte)0x9d, 
        (byte)0xc6, (byte)0x7e, (byte)0x37, (byte)0x83, 
        (byte)0x2b, (byte)0x76, (byte)0x53, (byte)0x8e, 
        (byte)0x62, (byte)0x4c, (byte)0x64, (byte)0x88, 
        (byte)0x44, (byte)0x8b, (byte)0xfb, (byte)0xa2, 
        (byte)0x17, (byte)0x9a, (byte)0x59, (byte)0xf5, 
        (byte)0x87, (byte)0xb3, (byte)0x4f, (byte)0x13, 
        (byte)0x61, (byte)0x45, (byte)0x6d, (byte)0x8d, 
        (byte)0x09, (byte)0x81, (byte)0x7d, (byte)0x32, 
        (byte)0xbd, (byte)0x8f, (byte)0x40, (byte)0xeb, 
        (byte)0x86, (byte)0xb7, (byte)0x7b, (byte)0xb, 
        (byte)0xf0, (byte)0x95, (byte)0x21, (byte)0x22, 
        (byte)0x5c, (byte)0x6b, (byte)0x4e, (byte)0x82, 
        (byte)0x54, (byte)0xd6, (byte)0x65, (byte)0x93, 
        (byte)0xce, (byte)0x60, (byte)0xb2, (byte)0x1c, 
        (byte)0x73, (byte)0x56, (byte)0xc0, (byte)0x14, 
        (byte)0xa7, (byte)0x8c, (byte)0xf1, (byte)0xdc, 
        (byte)0x12, (byte)0x75, (byte)0xca, (byte)0x1f, 
        (byte)0x3b, (byte)0xbe, (byte)0xe4, (byte)0xd1, 
        (byte)0x42, (byte)0x3d, (byte)0xd4, (byte)0x30, 
        (byte)0xa3, (byte)0x3c, (byte)0xb6, (byte)0x26, 
        (byte)0x6f, (byte)0xbf, (byte)0x0e, (byte)0xda, 
        (byte)0x46, (byte)0x69, (byte)0x07, (byte)0x57, 
        (byte)0x27, (byte)0xf2, (byte)0x1d, (byte)0x9b, 
        (byte)0xbc, (byte)0x94, (byte)0x43, (byte)0x03, 
        (byte)0xf8, (byte)0x11, (byte)0xc7, (byte)0xf6, 
        (byte)0x90, (byte)0xef, (byte)0x3e, (byte)0xe7, 
        (byte)0x06, (byte)0xc3, (byte)0xd5, (byte)0x2f, 
        (byte)0xc8, (byte)0x66, (byte)0x1e, (byte)0xd7, 
        (byte)0x08, (byte)0xe8, (byte)0xea, (byte)0xde, 
        (byte)0x80, (byte)0x52, (byte)0xee, (byte)0xf7, 
        (byte)0x84, (byte)0xaa, (byte)0x72, (byte)0xac, 
        (byte)0x35, (byte)0x4d, (byte)0x6a, (byte)0x2a, 
        (byte)0x96, (byte)0x1a, (byte)0xd2, (byte)0x71, 
        (byte)0x5a, (byte)0x15, (byte)0x49, (byte)0x74, 
        (byte)0x4b, (byte)0x9f, (byte)0xd0, (byte)0x5e, 
        (byte)0x04, (byte)0x18, (byte)0xa4, (byte)0xec, 
        (byte)0xc2, (byte)0xe0, (byte)0x41, (byte)0x6e, 
        (byte)0x0f, (byte)0x51, (byte)0xcb, (byte)0xcc, 
        (byte)0x24, (byte)0x91, (byte)0xaf, (byte)0x50, 
        (byte)0xa1, (byte)0xf4, (byte)0x70, (byte)0x39, 
        (byte)0x99, (byte)0x7c, (byte)0x3a, (byte)0x85, 
        (byte)0x23, (byte)0xb8, (byte)0xb4, (byte)0x7a, 
        (byte)0xfc, (byte)0x02, (byte)0x36, (byte)0x5b, 
        (byte)0x25, (byte)0x55, (byte)0x97, (byte)0x31, 
        (byte)0x2d, (byte)0x5d, (byte)0xfa, (byte)0x98, 
        (byte)0xe3, (byte)0x8a, (byte)0x92, (byte)0xae, 
        (byte)0x05, (byte)0xdf, (byte)0x29, (byte)0x10, 
        (byte)0x67, (byte)0x6c, (byte)0xba, (byte)0xc9, 
        (byte)0xd3, (byte)0x00, (byte)0xe6, (byte)0xcf, 
        (byte)0xe1, (byte)0x9e, (byte)0xa8, (byte)0x2c, 
        (byte)0x63, (byte)0x16, (byte)0x01, (byte)0x3f, 
        (byte)0x58, (byte)0xe2, (byte)0x89, (byte)0xa9, 
        (byte)0x0d, (byte)0x38, (byte)0x34, (byte)0x1b, 
        (byte)0xab, (byte)0x33, (byte)0xff, (byte)0xb0, 
        (byte)0xbb, (byte)0x48, (byte)0x0c, (byte)0x5f, 
        (byte)0xb9, (byte)0xb1, (byte)0xcd, (byte)0x2e, 
        (byte)0xc5, (byte)0xf3, (byte)0xdb, (byte)0x47, 
        (byte)0xe5, (byte)0xa5, (byte)0x9c, (byte)0x77, 
        (byte)0x0a, (byte)0xa6, (byte)0x20, (byte)0x68, 
        (byte)0xfe, (byte)0x7f, (byte)0xc1, (byte)0xad 
    };
    private static int rotateWordLeft(int x, int y)
    {
        return ((x & 0xffff) << y) | ((x & 0xffff) >> (16 - y));
    }
	///////////////////////////////////////////////////////////////////////////
	// Создать расписание ключей
	///////////////////////////////////////////////////////////////////////////
    private static int[] getKeys(byte[] key, int effectiveKeyBits)
    {
        // выделить буфер для расширения ключа
        byte[] xKey = new byte[128]; int len = key.length;
        
        // скопировать ключ
        System.arraycopy(key, 0, xKey, 0, len);
        
        // Phase 1: Expand input key to 128 bytes
        for (int index = 0; index < 128 - len; index++)
        {
            xKey[len + index] = piTable[(xKey[len + index - 1] + xKey[index]) & 0xff];
        }
        // Phase 2 - reduce effective key size to "bits"
        int T8 = (effectiveKeyBits + 7) / 8; int TM = 255 >>> (7 & -effectiveKeyBits); 

        xKey[128 - T8] = piTable[xKey[128 - T8] & TM];

        for (int i = 128 - T8 - 1; i >= 0; i--)
        {
            xKey[i] = piTable[(xKey[i + 1] ^ xKey[i + T8]) & 0xff];
        }
        // Phase 3 - copy to newKey in little-endian order 
        int[] newKey = new int[64];
        for (int i = 0; i < newKey.length; i++)
        {
            newKey[i] = Convert.toInt16(xKey, 2 * i, ENDIAN) & 0xffff; 
        }
        return newKey;
    }
    ////////////////////////////////////////////////////////////////////////////
    // Тесты известных ответов
    ////////////////////////////////////////////////////////////////////////////
    public static void test63(Cipher engine) throws Exception
    {
        if (KeySizes.contains(engine.keyFactory().keySizes(), 8))
        Cipher.knownTest(engine, PaddingMode.NONE, new byte[] {
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00
        }, new byte[] {
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00
        }, new byte[] {
            (byte)0xeb, (byte)0xb7, (byte)0x73, (byte)0xf9, 
            (byte)0x93, (byte)0x27, (byte)0x8e, (byte)0xff
        }); 
    }
    public static void test64(Cipher engine) throws Exception
    {
        int[] keySizes = engine.keyFactory().keySizes(); 
        
        if (KeySizes.contains(keySizes, 8))
        Cipher.knownTest(engine, PaddingMode.NONE, new byte[] {
            (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff,
            (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff
        }, new byte[] {
            (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff,
            (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff
        }, new byte[] {
            (byte)0x27, (byte)0x8b, (byte)0x27, (byte)0xe4, 
            (byte)0x2e, (byte)0x2f, (byte)0x0d, (byte)0x49
        }); 
        if (KeySizes.contains(keySizes, 8))
        Cipher.knownTest(engine, PaddingMode.NONE, new byte[] {
            (byte)0x30, (byte)0x00, (byte)0x00, (byte)0x00,
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00
        }, new byte[] {
            (byte)0x10, (byte)0x00, (byte)0x00, (byte)0x00,
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x01
        }, new byte[] {
            (byte)0x30, (byte)0x64, (byte)0x9e, (byte)0xdf, 
            (byte)0x9b, (byte)0xe7, (byte)0xd2, (byte)0xc2
        }); 
        if (KeySizes.contains(keySizes, 1))
        Cipher.knownTest(engine, PaddingMode.NONE, new byte[] {
            (byte)0x88
        }, new byte[] {
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00
        }, new byte[] {
            (byte)0x61, (byte)0xa8, (byte)0xa2, (byte)0x44, 
            (byte)0xad, (byte)0xac, (byte)0xcc, (byte)0xf0
        }); 
        if (KeySizes.contains(keySizes, 7))
        Cipher.knownTest(engine, PaddingMode.NONE, new byte[] {
            (byte)0x88, (byte)0xbc, (byte)0xa9, (byte)0x0e, 
            (byte)0x90, (byte)0x87, (byte)0x5a
        }, new byte[] {
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00
        }, new byte[] {
            (byte)0x6c, (byte)0xcf, (byte)0x43, (byte)0x08, 
            (byte)0x97, (byte)0x4c, (byte)0x26, (byte)0x7f
        }); 
        if (KeySizes.contains(keySizes, 16))
        Cipher.knownTest(engine, PaddingMode.NONE, new byte[] {
            (byte)0x88, (byte)0xbc, (byte)0xa9, (byte)0x0e, 
            (byte)0x90, (byte)0x87, (byte)0x5a, (byte)0x7f, 
            (byte)0x0f, (byte)0x79, (byte)0xc3, (byte)0x84, 
            (byte)0x62, (byte)0x7b, (byte)0xaf, (byte)0xb2
        }, new byte[] {
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00
        }, new byte[] {
            (byte)0x1a, (byte)0x80, (byte)0x7d, (byte)0x27, 
            (byte)0x2b, (byte)0xbe, (byte)0x5d, (byte)0xb1
        }); 
    }
    public static void test128(Cipher engine) throws Exception
    {
        if (KeySizes.contains(engine.keyFactory().keySizes(), 16))
        Cipher.knownTest(engine, PaddingMode.NONE, new byte[] {
            (byte)0x88, (byte)0xbc, (byte)0xa9, (byte)0x0e, 
            (byte)0x90, (byte)0x87, (byte)0x5a, (byte)0x7f, 
            (byte)0x0f, (byte)0x79, (byte)0xc3, (byte)0x84, 
            (byte)0x62, (byte)0x7b, (byte)0xaf, (byte)0xb2
        }, new byte[] {
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00
        }, new byte[] {
            (byte)0x22, (byte)0x69, (byte)0x55, (byte)0x2a,
            (byte)0xb0, (byte)0xf8, (byte)0x5c, (byte)0xa6
        }); 
    }
    public static void test129(Cipher engine) throws Exception
    {
        if (KeySizes.contains(engine.keyFactory().keySizes(), 33))
        Cipher.knownTest(engine, PaddingMode.NONE, new byte[] {
            (byte)0x88, (byte)0xbc, (byte)0xa9, (byte)0x0e, 
            (byte)0x90, (byte)0x87, (byte)0x5a, (byte)0x7f, 
            (byte)0x0f, (byte)0x79, (byte)0xc3, (byte)0x84, 
            (byte)0x62, (byte)0x7b, (byte)0xaf, (byte)0xb2, 
            (byte)0x16, (byte)0xf8, (byte)0x0a, (byte)0x6f, 
            (byte)0x85, (byte)0x92, (byte)0x05, (byte)0x84,
            (byte)0xc4, (byte)0x2f, (byte)0xce, (byte)0xb0, 
            (byte)0xbe, (byte)0x25, (byte)0x5d, (byte)0xaf, 
            (byte)0x1e
        }, new byte[] {
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00
        }, new byte[] {
            (byte)0x5b, (byte)0x78, (byte)0xd3, (byte)0xa4, 
            (byte)0x3d, (byte)0xff, (byte)0xf1, (byte)0xf1
        }); 
    }
}
