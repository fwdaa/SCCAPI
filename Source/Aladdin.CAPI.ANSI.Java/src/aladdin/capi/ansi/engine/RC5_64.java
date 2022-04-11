package aladdin.capi.ansi.engine;
import aladdin.math.*;
import aladdin.capi.*; 
import java.security.*; 

///////////////////////////////////////////////////////////////////////////
// Алгоритм шифрования RC5
///////////////////////////////////////////////////////////////////////////
public final class RC5_64 extends Cipher
{
    // способ кодирования чисел
    private static final Endian ENDIAN = Endian.LITTLE_ENDIAN; 
    
    // число раундов и допустимые размеры ключей
    private final int rounds; private final int[] keySizes;
        
    // конструктор
    public RC5_64(int rounds) { this(rounds, KeySizes.range(1, 256)); }
    // конструктор
    public RC5_64(int rounds, int[] keySizes) 
    { 
        // сохранить переданные параметры
        this.rounds = rounds; this.keySizes = keySizes; 
    } 
    // тип ключа
    @Override public final SecretKeyFactory keyFactory() 
    { 
        // тип ключа
        return new aladdin.capi.ansi.keys.RC5(keySizes); 
    } 
    // размер блока
	@Override public final int blockSize() { return 8; }

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
        return new Encryption(key, rounds); 
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
		return new Decryption(key, rounds); 
	}
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм зашифрования блока
	///////////////////////////////////////////////////////////////////////////
	public static class Encryption extends BlockTransform
	{
		// расписание ключей и число раундов
		private final int[] keys; private final int rounds; 
        
		// Конструктор
		public Encryption(ISecretKey key, int rounds) throws InvalidKeyException 
		{ 
			// сохранить переданные параметры
			super(8); this.rounds = rounds; 
            
			// проверить тип ключа
            if (key.value() == null) throw new InvalidKeyException();

            // создать расписание ключей
            keys = getKeys(key.value(), rounds); 
        }
		///////////////////////////////////////////////////////////////////////
		// Обработка одного блока данных
		///////////////////////////////////////////////////////////////////////
		@Override protected void update(byte[] src, int srcOff, byte[] dest, int destOff)
		{
            int A = Convert.toInt32(src, srcOff + 0, ENDIAN) + keys[0];
            int B = Convert.toInt32(src, srcOff + 4, ENDIAN) + keys[1];

            for (int i = 1; i <= rounds; i++)
            {
                A = rotateLeft(A ^ B, B) + keys[2 * i + 0];
                B = rotateLeft(B ^ A, A) + keys[2 * i + 1];
            }
            Convert.fromInt32(A, ENDIAN, dest, destOff + 0);
            Convert.fromInt32(B, ENDIAN, dest, destOff + 4); 
        }
	}
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм расшифрования блока
	///////////////////////////////////////////////////////////////////////////
	public static class Decryption extends BlockTransform
	{
		// расписание ключей и число раундов
		private final int[] keys; private final int rounds; 

		// Конструктор
		public Decryption(ISecretKey key, int rounds) throws InvalidKeyException
		{ 
			// сохранить переданные параметры
			super(8); this.rounds = rounds; 
            
			// проверить тип ключа
            if (key.value() == null) throw new InvalidKeyException();

            // создать расписание ключей
            keys = getKeys(key.value(), rounds); 
        }
		///////////////////////////////////////////////////////////////////////
		// Обработка одного блока данных
		///////////////////////////////////////////////////////////////////////
		@Override protected void update(byte[] src, int srcOff, byte[] dest, int destOff)
		{
            int A = Convert.toInt32(src, srcOff + 0, ENDIAN);
            int B = Convert.toInt32(src, srcOff + 4, ENDIAN);

            for (int i = rounds; i >= 1; i--)
            {
                B = rotateRight(B - keys[2 * i + 1], A) ^ A;
                A = rotateRight(A - keys[2 * i + 0], B) ^ B;
            }
            Convert.fromInt32(A - keys[0], ENDIAN, dest, destOff + 0);
            Convert.fromInt32(B - keys[1], ENDIAN, dest, destOff + 4); 
		}
	}
	///////////////////////////////////////////////////////////////////////////
	// Вспомогательные функции
	///////////////////////////////////////////////////////////////////////////
    /*
     * our "magic constants" for 32 32
     *
     * Pw = Odd((e-2) * 2^wordsize)
     * Qw = Odd((o-2) * 2^wordsize)
     *
     * where e is the base of natural logarithms (2.718281828...)
     * and o is the golden ratio (1.61803398...)
     */
    private static final int P32 = 0xb7e15163;
    private static final int Q32 = 0x9e3779b9;

    private static int rotateLeft(int x, int y)
    {
        return ((x << (y & 0x1F)) | (x >>> (32 - (y & 0x1F))));
    }
    private static int rotateRight(int x, int y)
    {
        return ((x >>> (y & 0x1F)) | (x << (32 - (y & 0x1F))));
    }
	///////////////////////////////////////////////////////////////////////////
	// Создать расписание ключей
	///////////////////////////////////////////////////////////////////////////
    private static int[] getKeys(byte[] key, int rounds)
    {
        //
        // KEY EXPANSION:
        //
        // There are 3 phases to the key expansion.
        //
        // Phase 1:
        //   Copy the secret key K[0...b-1] into an array L[0..c-1] of
        //   c = ceil(b/u), where u = 32/8 in little-endian order.
        //   In other words, we fill up L using u consecutive key bytes
        //   of K. Any unfilled byte positions in L are zeroed. In the
        //   case that b = c = 0, set c = 1 and L[0] = 0.
        //
        int[] L = new int[(key.length + 3) / 4];

        for (int i = 0; i < key.length; i++)
        {
            L[i / 4] += (key[i] & 0xff) << (8 * (i % 4));
        }
        //
        // Phase 2:
        //   Initialize S to a particular fixed pseudo-random bit pattern
        //   using an arithmetic progression modulo 2^wordsize determined
        //   by the magic numbers, Pw & Qw.
        //
        int[] S = new int[2 * (rounds + 1)]; S[0] = P32;
        
        for (int i = 1; i < S.length; i++) S[i] = S[i - 1] + Q32;
        //
        // Phase 3:
        //   Mix in the user's secret key in 3 passes over the arrays S & L.
        //   The max of the arrays sizes is used as the loop control
        //
        int iter = (L.length > S.length) ? 3 * L.length : 3 * S.length;

        int A = 0; int B = 0; 
        for (int i = 0, j = 0, k = 0; k < iter; k++)
        {
            A = S[i] = rotateLeft(S[i] + A + B,     3);
            B = L[j] = rotateLeft(L[j] + A + B, A + B);
            
            i = (i + 1) %  S.length;
            j = (j + 1) %  L.length;
        }
        return S; 
    }
    ////////////////////////////////////////////////////////////////////////////
    // Тесты известного ответа
    ////////////////////////////////////////////////////////////////////////////
    public static void test0(IBlockCipher blockCipher) throws Exception
    {
        // определить размер ключей
        int[] keySizes = blockCipher.keyFactory().keySizes(); 
            
        // указать требуемый режим
        CipherMode.CBC mode = new CipherMode.CBC(new byte[] { 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00
        }); 
        // получить требуемый режим
        try (Cipher cipher = blockCipher.createBlockMode(mode))
        {
            // выполнить тест
            if (KeySizes.contains(keySizes, 1))
            Cipher.knownTest(cipher, PaddingMode.NONE, new byte[] { 
                (byte)0x00 
            }, new byte[] { 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00 
            }, new byte[] { 
                (byte)0x7a, (byte)0x7b, (byte)0xba, (byte)0x4d, 
                (byte)0x79, (byte)0x11, (byte)0x1d, (byte)0x1e
            }); 
            if (KeySizes.contains(keySizes, 1))
            Cipher.knownTest(cipher, PaddingMode.NONE, new byte[] { 
                (byte)0x00 
            }, new byte[] { 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x01
            }, new byte[] { 
                (byte)0x7a, (byte)0x7b, (byte)0xba, (byte)0x4d, 
                (byte)0x79, (byte)0x11, (byte)0x1d, (byte)0x1f
            }); 
            if (KeySizes.contains(keySizes, 1))
            Cipher.knownTest(cipher, PaddingMode.NONE, new byte[] { 
                (byte)0x00 
            }, new byte[] { 
                (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, 
                (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff 
            }, new byte[] { 
                (byte)0x79, (byte)0x7b, (byte)0xba, (byte)0x4d, 
                (byte)0x78, (byte)0x11, (byte)0x1d, (byte)0x1e
            }); 
        }
        // указать требуемый режим
        mode = new CipherMode.CBC(new byte[] { 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x01
        }); 
        // получить требуемый режим
        try (Cipher cipher = blockCipher.createBlockMode(mode))
        {
            // выполнить тест
            if (KeySizes.contains(keySizes, 1))
            Cipher.knownTest(cipher, PaddingMode.NONE, new byte[] { 
                (byte)0x00 
            }, new byte[] { 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00
            }, new byte[] { 
                (byte)0x7a, (byte)0x7b, (byte)0xba, (byte)0x4d, 
                (byte)0x79, (byte)0x11, (byte)0x1d, (byte)0x1f
            }); 
        }
        // указать требуемый режим
        mode = new CipherMode.CBC(new byte[] { 
            (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, 
            (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08
        }); 
        // получить требуемый режим
        try (Cipher cipher = blockCipher.createBlockMode(mode))
        {
            // выполнить тест
            if (KeySizes.contains(keySizes, 1))
            Cipher.knownTest(cipher, PaddingMode.NONE, new byte[] { 
                (byte)0x00 
            }, new byte[] { 
                (byte)0x10, (byte)0x20, (byte)0x30, (byte)0x40, 
                (byte)0x50, (byte)0x60, (byte)0x70, (byte)0x80 
            }, new byte[] { 
                (byte)0x8b, (byte)0x9d, (byte)0xed, (byte)0x91, 
                (byte)0xce, (byte)0x77, (byte)0x94, (byte)0xa6
            }); 
        }
    }
    public static void test1(IBlockCipher blockCipher) throws Exception
    {
        // определить размер ключей
        int[] keySizes = blockCipher.keyFactory().keySizes(); 
        
        // указать требуемый режим
        CipherMode.CBC mode = new CipherMode.CBC(new byte[] { 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00
        }); 
        // получить требуемый режим
        try (Cipher cipher = blockCipher.createBlockMode(mode))
        {
            // выполнить тест
            if (KeySizes.contains(keySizes, 1))
            Cipher.knownTest(cipher, PaddingMode.NONE, new byte[] { 
                (byte)0x11 
            }, new byte[] { 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00
            }, new byte[] { 
                (byte)0x2f, (byte)0x75, (byte)0x9f, (byte)0xe7, 
                (byte)0xad, (byte)0x86, (byte)0xa3, (byte)0x78
            }); 
        }
    }
    public static void test2(IBlockCipher blockCipher) throws Exception
    {
        // определить размер ключей
        int[] keySizes = blockCipher.keyFactory().keySizes(); 
        
        // указать требуемый режим
        CipherMode.CBC mode = new CipherMode.CBC(new byte[] { 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00
        }); 
        // получить требуемый режим
        try (Cipher cipher = blockCipher.createBlockMode(mode))
        {
            // выполнить тест
            if (KeySizes.contains(keySizes, 1))
            Cipher.knownTest(cipher, PaddingMode.NONE, new byte[] { 
                (byte)0x00 
            }, new byte[] { 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00
            }, new byte[] { 
                (byte)0xdc, (byte)0xa2, (byte)0x69, (byte)0x4b, 
                (byte)0xf4, (byte)0x0e, (byte)0x07, (byte)0x88
            }); 
            // выполнить тест
            if (KeySizes.contains(keySizes, 4))
            Cipher.knownTest(cipher, PaddingMode.NONE, new byte[] { 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00 
            }, new byte[] { 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00
            }, new byte[] { 
                (byte)0xdc, (byte)0xa2, (byte)0x69, (byte)0x4b, 
                (byte)0xf4, (byte)0x0e, (byte)0x07, (byte)0x88
            }); 
        }
    }
    public static void test8(IBlockCipher blockCipher) throws Exception
    {
        // определить размер ключей
        int[] keySizes = blockCipher.keyFactory().keySizes(); 
        
        // указать требуемый режим
        CipherMode.CBC mode = new CipherMode.CBC(new byte[] { 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00
        }); 
        // получить требуемый режим
        try (Cipher cipher = blockCipher.createBlockMode(mode))
        {
            // выполнить тест
            if (KeySizes.contains(keySizes, 1))
            Cipher.knownTest(cipher, PaddingMode.NONE, new byte[] { 
                (byte)0x00 
            }, new byte[] { 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00
            }, new byte[] { 
                (byte)0xdc, (byte)0xfe, (byte)0x09, (byte)0x85, 
                (byte)0x77, (byte)0xec, (byte)0xa5, (byte)0xff
            }); 
            // выполнить тест
            if (KeySizes.contains(keySizes, 4))
            Cipher.knownTest(cipher, PaddingMode.NONE, new byte[] { 
                (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04 
            }, new byte[] { 
                (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, 
                (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff 
            }, new byte[] { 
                (byte)0x82, (byte)0x85, (byte)0xe7, (byte)0xc1, 
                (byte)0xb5, (byte)0xbc, (byte)0x74, (byte)0x02
            }); 
            // выполнить тест
            if (KeySizes.contains(keySizes, 5))
            Cipher.knownTest(cipher, PaddingMode.NONE, new byte[] { 
                (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, 
                (byte)0x05 
            }, new byte[] { 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00
            }, new byte[] { 
                (byte)0x7c, (byte)0xb3, (byte)0xf1, (byte)0xdf, 
                (byte)0x34, (byte)0xf9, (byte)0x48, (byte)0x11
            }); 
            // выполнить тест
            if (KeySizes.contains(keySizes, 5))
            Cipher.knownTest(cipher, PaddingMode.NONE, new byte[] { 
                (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, 
                (byte)0x05 
            }, new byte[] { 
                (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, 
                (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff 
            }, new byte[] { 
                (byte)0x78, (byte)0x75, (byte)0xdb, (byte)0xf6, 
                (byte)0x73, (byte)0x8c, (byte)0x64, (byte)0x78
            }); 
            // выполнить тест
            if (KeySizes.contains(keySizes, 5))
            Cipher.knownTest(cipher, PaddingMode.PKCS5, new byte[] { 
                (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, 
                (byte)0x05 
            }, new byte[] { 
                (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, 
                (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff 
            }, new byte[] { 
                (byte)0x78, (byte)0x75, (byte)0xdb, (byte)0xf6, 
                (byte)0x73, (byte)0x8c, (byte)0x64, (byte)0x78, 
                (byte)0x8f, (byte)0x34, (byte)0xc3, (byte)0xc6, 
                (byte)0x81, (byte)0xc9, (byte)0x96, (byte)0x95
            }); 
            // выполнить тест
            if (KeySizes.contains(keySizes, 5))
            Cipher.knownTest(cipher, PaddingMode.PKCS5, new byte[] { 
                (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, 
                (byte)0x05 
            }, new byte[] { 
                (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, 
                (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, 
                (byte)0x78, (byte)0x75, (byte)0xdb, (byte)0xf6, 
                (byte)0x73, (byte)0x8c, (byte)0x64, (byte)0x78, 
                (byte)0x11, (byte)0x22, (byte)0x33, (byte)0x44, 
                (byte)0x55, (byte)0x66, (byte)0x77
            }, new byte[] { 
                (byte)0x78, (byte)0x75, (byte)0xdb, (byte)0xf6, 
                (byte)0x73, (byte)0x8c, (byte)0x64, (byte)0x78, 
                (byte)0x7c, (byte)0xb3, (byte)0xf1, (byte)0xdf, 
                (byte)0x34, (byte)0xf9, (byte)0x48, (byte)0x11, 
                (byte)0x7f, (byte)0xd1, (byte)0xa0, (byte)0x23, 
                (byte)0xa5, (byte)0xbb, (byte)0xa2, (byte)0x17
            }); 
        }
        // указать требуемый режим
        mode = new CipherMode.CBC(new byte[] { 
            (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, 
            (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08
        }); 
        // получить требуемый режим
        try (Cipher cipher = blockCipher.createBlockMode(mode))
        {
            // выполнить тест
            if (KeySizes.contains(keySizes, 1))
            Cipher.knownTest(cipher, PaddingMode.NONE, new byte[] { 
                (byte)0x00 
            }, new byte[] { 
                (byte)0x10, (byte)0x20, (byte)0x30, (byte)0x40, 
                (byte)0x50, (byte)0x60, (byte)0x70, (byte)0x80 
            }, new byte[] { 
                (byte)0x96, (byte)0x46, (byte)0xfb, (byte)0x77, 
                (byte)0x63, (byte)0x8f, (byte)0x9c, (byte)0xa8
            }); 
            // выполнить тест
            if (KeySizes.contains(keySizes, 8))
            Cipher.knownTest(cipher, PaddingMode.NONE, new byte[] { 
                (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, 
                (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08
            }, new byte[] { 
                (byte)0x10, (byte)0x20, (byte)0x30, (byte)0x40, 
                (byte)0x50, (byte)0x60, (byte)0x70, (byte)0x80 
            }, new byte[] { 
                (byte)0x5c, (byte)0x4c, (byte)0x04, (byte)0x1e, 
                (byte)0x0f, (byte)0x21, (byte)0x7a, (byte)0xc3
            }); 
            // выполнить тест
            if (KeySizes.contains(keySizes, 16))
            Cipher.knownTest(cipher, PaddingMode.NONE, new byte[] { 
                (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, 
                (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08, 
                (byte)0x10, (byte)0x20, (byte)0x30, (byte)0x40, 
                (byte)0x50, (byte)0x60, (byte)0x70, (byte)0x80
            }, new byte[] { 
                (byte)0x10, (byte)0x20, (byte)0x30, (byte)0x40, 
                (byte)0x50, (byte)0x60, (byte)0x70, (byte)0x80 
            }, new byte[] { 
                (byte)0xc5, (byte)0x33, (byte)0x77, (byte)0x1c, 
                (byte)0xd0, (byte)0x11, (byte)0x0e, (byte)0x63
            }); 
        }
        // указать требуемый режим
        mode = new CipherMode.CBC(new byte[] { 
            (byte)0x78, (byte)0x75, (byte)0xdb, (byte)0xf6, 
            (byte)0x73, (byte)0x8c, (byte)0x64, (byte)0x78
        });         
        // получить требуемый режим
        try (Cipher cipher = blockCipher.createBlockMode(mode))
        {
            // выполнить тест
            if (KeySizes.contains(keySizes, 5))
            Cipher.knownTest(cipher, PaddingMode.NONE, new byte[] { 
                (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, 
                (byte)0x05 
            }, new byte[] { 
                (byte)0x08, (byte)0x08, (byte)0x08, (byte)0x08, 
                (byte)0x08, (byte)0x08, (byte)0x08, (byte)0x08 
            }, new byte[] { 
                (byte)0x8f, (byte)0x34, (byte)0xc3, (byte)0xc6, 
                (byte)0x81, (byte)0xc9, (byte)0x96, (byte)0x95
            }); 
        }
        // указать требуемый режим
        mode = new CipherMode.CBC(new byte[] { 
            (byte)0x7c, (byte)0xb3, (byte)0xf1, (byte)0xdf, 
            (byte)0x34, (byte)0xf9, (byte)0x48, (byte)0x11
        });         
        // получить требуемый режим
        try (Cipher cipher = blockCipher.createBlockMode(mode))
        {
            // выполнить тест
            if (KeySizes.contains(keySizes, 5))
            Cipher.knownTest(cipher, PaddingMode.NONE, new byte[] { 
                (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, 
                (byte)0x05 
            }, new byte[] { 
                (byte)0x11, (byte)0x22, (byte)0x33, (byte)0x44, 
                (byte)0x55, (byte)0x66, (byte)0x77, (byte)0x01 
            }, new byte[] { 
                (byte)0x7f, (byte)0xd1, (byte)0xa0, (byte)0x23, 
                (byte)0xa5, (byte)0xbb, (byte)0xa2, (byte)0x17
            }); 
        }
    }
    public static void test12(IBlockCipher blockCipher) throws Exception
    {
        // определить размер ключей
        int[] keySizes = blockCipher.keyFactory().keySizes(); 
        
        // указать требуемый режим
        CipherMode.CBC mode = new CipherMode.CBC(new byte[] { 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00
        });         
        // получить требуемый режим
        try (Cipher cipher = blockCipher.createBlockMode(mode))
        {
            // выполнить тест
            if (KeySizes.contains(keySizes, 4))
            Cipher.knownTest(cipher, PaddingMode.NONE, new byte[] { 
                (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04 
            }, new byte[] { 
                (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, 
                (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff 
            }, new byte[] { 
                (byte)0xfc, (byte)0x58, (byte)0x6f, (byte)0x92, 
                (byte)0xf7, (byte)0x08, (byte)0x09, (byte)0x34
            }); 
            // выполнить тест
            if (KeySizes.contains(keySizes, 5))
            Cipher.knownTest(cipher, PaddingMode.NONE, new byte[] { 
                (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, 
                (byte)0x05 
            }, new byte[] { 
                (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, 
                (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff 
            }, new byte[] { 
                (byte)0x97, (byte)0xe0, (byte)0x78, (byte)0x78, 
                (byte)0x37, (byte)0xed, (byte)0x31, (byte)0x7f
            }); 
            // выполнить тест
            if (KeySizes.contains(keySizes, 8))
            Cipher.knownTest(cipher, PaddingMode.NONE, new byte[] { 
                (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, 
                (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08 
            }, new byte[] { 
                (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, 
                (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff 
            }, new byte[] { 
                (byte)0xe4, (byte)0x93, (byte)0xf1, (byte)0xc1, 
                (byte)0xbb, (byte)0x4d, (byte)0x6e, (byte)0x8c
            }); 
        }
        // указать требуемый режим
        mode = new CipherMode.CBC(new byte[] { 
            (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, 
            (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08
        }); 
        // получить требуемый режим
        try (Cipher cipher = blockCipher.createBlockMode(mode))
        {
            // выполнить тест
            if (KeySizes.contains(keySizes, 1))
            Cipher.knownTest(cipher, PaddingMode.NONE, new byte[] { 
                (byte)0x00 
            }, new byte[] { 
                (byte)0x10, (byte)0x20, (byte)0x30, (byte)0x40, 
                (byte)0x50, (byte)0x60, (byte)0x70, (byte)0x80 
            }, new byte[] { 
                (byte)0xb2, (byte)0xb3, (byte)0x20, (byte)0x9d, 
                (byte)0xb6, (byte)0x59, (byte)0x4d, (byte)0xa4
            }); 
            // выполнить тест
            if (KeySizes.contains(keySizes, 8))
            Cipher.knownTest(cipher, PaddingMode.NONE, new byte[] { 
                (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, 
                (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08 
            }, new byte[] { 
                (byte)0x10, (byte)0x20, (byte)0x30, (byte)0x40, 
                (byte)0x50, (byte)0x60, (byte)0x70, (byte)0x80 
            }, new byte[] { 
                (byte)0x92, (byte)0x1f, (byte)0x12, (byte)0x48, 
                (byte)0x53, (byte)0x73, (byte)0xb4, (byte)0xf7
            }); 
            // выполнить тест
            if (KeySizes.contains(keySizes, 16))
            Cipher.knownTest(cipher, PaddingMode.NONE, new byte[] { 
                (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, 
                (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08, 
                (byte)0x10, (byte)0x20, (byte)0x30, (byte)0x40, 
                (byte)0x50, (byte)0x60, (byte)0x70, (byte)0x80
            }, new byte[] { 
                (byte)0x10, (byte)0x20, (byte)0x30, (byte)0x40, 
                (byte)0x50, (byte)0x60, (byte)0x70, (byte)0x80 
            }, new byte[] { 
                (byte)0x29, (byte)0x4d, (byte)0xdb, (byte)0x46, 
                (byte)0xb3, (byte)0x27, (byte)0x8d, (byte)0x60
            }); 
        }
    }
    public static void test16(IBlockCipher blockCipher) throws Exception
    {
        // определить размер ключей
        int[] keySizes = blockCipher.keyFactory().keySizes(); 
        
        // указать требуемый режим
        CipherMode.CBC mode = new CipherMode.CBC(new byte[] { 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00
        }); 
        // получить требуемый режим
        try (Cipher cipher = blockCipher.createBlockMode(mode))
        {
            // выполнить тест
            if (KeySizes.contains(keySizes, 4))
            Cipher.knownTest(cipher, PaddingMode.NONE, new byte[] { 
                (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04 
            }, new byte[] { 
                (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, 
                (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff 
            }, new byte[] { 
                (byte)0xcf, (byte)0x27, (byte)0x0e, (byte)0xf9, 
                (byte)0x71, (byte)0x7f, (byte)0xf7, (byte)0xc4
            }); 
        }
        // указать требуемый режим
        mode = new CipherMode.CBC(new byte[] { 
            (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, 
            (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08
        }); 
        // получить требуемый режим
        try (Cipher cipher = blockCipher.createBlockMode(mode))
        {
            // выполнить тест
            if (KeySizes.contains(keySizes, 1))
            Cipher.knownTest(cipher, PaddingMode.NONE, new byte[] { 
                (byte)0x00 
            }, new byte[] { 
                (byte)0x10, (byte)0x20, (byte)0x30, (byte)0x40, 
                (byte)0x50, (byte)0x60, (byte)0x70, (byte)0x80 
            }, new byte[] { 
                (byte)0x54, (byte)0x5f, (byte)0x7f, (byte)0x32, 
                (byte)0xa5, (byte)0xfc, (byte)0x38, (byte)0x36
            }); 
            // выполнить тест
            if (KeySizes.contains(keySizes, 8))
            Cipher.knownTest(cipher, PaddingMode.NONE, new byte[] { 
                (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, 
                (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08 
            }, new byte[] { 
                (byte)0x10, (byte)0x20, (byte)0x30, (byte)0x40, 
                (byte)0x50, (byte)0x60, (byte)0x70, (byte)0x80 
            }, new byte[] { 
                (byte)0x5b, (byte)0xa0, (byte)0xca, (byte)0x6b, 
                (byte)0xbe, (byte)0x7f, (byte)0x5f, (byte)0xad
            }); 
            // выполнить тест
            if (KeySizes.contains(keySizes, 16))
            Cipher.knownTest(cipher, PaddingMode.NONE, new byte[] { 
                (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, 
                (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08, 
                (byte)0x10, (byte)0x20, (byte)0x30, (byte)0x40, 
                (byte)0x50, (byte)0x60, (byte)0x70, (byte)0x80
            }, new byte[] { 
                (byte)0x10, (byte)0x20, (byte)0x30, (byte)0x40, 
                (byte)0x50, (byte)0x60, (byte)0x70, (byte)0x80 
            }, new byte[] { 
                (byte)0xda, (byte)0xd6, (byte)0xbd, (byte)0xa9, 
                (byte)0xdf, (byte)0xe8, (byte)0xf7, (byte)0xe8
            }); 
        }
    }
}
