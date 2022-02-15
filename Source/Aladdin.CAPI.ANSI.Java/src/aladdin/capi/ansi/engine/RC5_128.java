package aladdin.capi.ansi.engine;
import aladdin.math.*;
import aladdin.capi.*; 
import java.security.*; 

///////////////////////////////////////////////////////////////////////////
// Алгоритм шифрования RC5
///////////////////////////////////////////////////////////////////////////
public final class RC5_128 extends Cipher
{
    // способ кодирования чисел
    private static final Endian ENDIAN = Endian.LITTLE_ENDIAN; 
    
    // конструктор
    public RC5_128(int rounds) { this.rounds = rounds; } private final int rounds;
        
    // тип ключа
    @Override public final SecretKeyFactory keyFactory() 
    { 
        // тип ключа
        return aladdin.capi.ansi.keys.RC5.INSTANCE; 
    } 
    // размер блока
	@Override public final int blockSize() { return 16; }

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
        if (value.length >= 256) throw new InvalidKeyException();
                
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
        if (value.length >= 256) throw new InvalidKeyException();
            
		// вернуть алгоритм расшифрования блока данных
		return new Decryption(key, rounds); 
	}
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм зашифрования блока
	///////////////////////////////////////////////////////////////////////////
	public static class Encryption extends BlockTransform
	{
		// расписание ключей и число раундов
		private final long[] keys; private final int rounds; 
        
		// Конструктор
		public Encryption(ISecretKey key, int rounds) throws InvalidKeyException
		{ 
			// сохранить переданные параметры
			super(16); this.rounds = rounds; 
            
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
            long A = Convert.toInt64(src, srcOff + 0, ENDIAN) + keys[0];
            long B = Convert.toInt64(src, srcOff + 8, ENDIAN) + keys[1];

            for (int i = 1; i <= rounds; i++)
            {
                A = rotateLeft(A ^ B, B) + keys[2 * i + 0];
                B = rotateLeft(B ^ A, A) + keys[2 * i + 1];
            }
            Convert.fromInt64(A, ENDIAN, dest, destOff + 0);
            Convert.fromInt64(B, ENDIAN, dest, destOff + 8); 
        }
	}
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм расшифрования блока
	///////////////////////////////////////////////////////////////////////////
	public static class Decryption extends BlockTransform
	{
		// расписание ключей и число раундов
		private final long[] keys; private final int rounds; 
        
		// Конструктор
		public Decryption(ISecretKey key, int rounds) throws InvalidKeyException
		{ 
			// сохранить переданные параметры
			super(16); this.rounds = rounds; 
            
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
            long A = Convert.toInt64(src, srcOff + 0, ENDIAN);
            long B = Convert.toInt64(src, srcOff + 8, ENDIAN);

            for (int i = rounds; i >= 1; i--)
            {
                B = rotateRight(B - keys[2 * i + 1], A) ^ A;
                A = rotateRight(A - keys[2 * i + 0], B) ^ B;
            }
            Convert.fromInt64(A - keys[0], ENDIAN, dest, destOff + 0);
            Convert.fromInt64(B - keys[1], ENDIAN, dest, destOff + 8); 
		}
	}
	///////////////////////////////////////////////////////////////////////////
	// Вспомогательные функции
	///////////////////////////////////////////////////////////////////////////
    /*
     * our "magic constants" for wordSize 62
     *
     * Pw = Odd((e-2) * 2^wordsize)
     * Qw = Odd((o-2) * 2^wordsize)
     *
     * where e is the base of natural logarithms (2.718281828...)
     * and o is the golden ratio (1.61803398...)
     */
    private static final long P64 = 0xb7e151628aed2a6bL;
    private static final long Q64 = 0x9e3779b97f4a7c15L;

    private static long rotateLeft(long x, long y)
    {
        return ((x << (y & 0x3F)) | (x >>> (64 - (y & 0x3F))));
    }
    private static long rotateRight(long x, long y)
    {
        return ((x >>> (y & 0x3F)) | (x << (64 - (y & 0x3F))));
    }
	///////////////////////////////////////////////////////////////////////////
	// Создать расписание ключей
	///////////////////////////////////////////////////////////////////////////
    private static long[] getKeys(byte[] key, int rounds)
    {
        //
        // KEY EXPANSION:
        //
        // There are 3 phases to the key expansion.
        //
        // Phase 1:
        //   Copy the secret key K[0...b-1] into an array L[0..c-1] of
        //   c = ceil(b/u), where u = wordSize/8 in little-endian order.
        //   In other words, we fill up L using u consecutive key bytes
        //   of K. Any unfilled byte positions in L are zeroed. In the
        //   case that b = c = 0, set c = 1 and L[0] = 0.
        //
        long[] L = new long[(key.length + 7) / 8];

        for (int i = 0; i < key.length; i++)
        {
            L[i / 8] += (long)(key[i] & 0xff) << (8 * (i % 8));
        }
        //
        // Phase 2:
        //   Initialize S to a particular fixed pseudo-random bit pattern
        //   using an arithmetic progression modulo 2^wordsize determined
        //   by the magic numbers, Pw & Qw.
        //
        long[] S = new long[2 * (rounds + 1)]; S[0] = P64;
        
        for (int i = 1; i < S.length; i++) S[i] = S[i - 1] + Q64;
        //
        // Phase 3:
        //   Mix in the user's secret key in 3 passes over the arrays S & L.
        //   The max of the arrays sizes is used as the loop control
        //
        int iter = (L.length > S.length) ? 3 * L.length : 3 * S.length;

        long A = 0; long B = 0; 
        for (int i = 0, j = 0, k = 0; k < iter; k++)
        {
            A = S[i] = rotateLeft(S[i] + A + B,     3);
            B = L[j] = rotateLeft(L[j] + A + B, A + B);
            
            i = (i + 1) %  S.length;
            j = (j + 1) %  L.length;
        }
        return S; 
    }
}
