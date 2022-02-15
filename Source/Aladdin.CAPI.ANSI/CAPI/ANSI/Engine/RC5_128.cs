using System;

namespace Aladdin.CAPI.ANSI.Engine
{
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм шифрования RC5
    ///////////////////////////////////////////////////////////////////////////
    public class RC5_128 : CAPI.Cipher
    {
        // способ кодирования чисел
        private const Math.Endian Endian = Math.Endian.LittleEndian; 
    
        // конструктор
        public RC5_128(int rounds) { this.rounds = rounds; } private int rounds;

        // тип ключа
        public override SecretKeyFactory KeyFactory { get { return Keys.RC5.Instance; }}
        // размер блока
		public override int BlockSize { get { return 16; }}

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
            if (value.Length >= 256) throw new InvalidKeyException();

            // вернуть алгоритм зашифрования блока данных
		    return new Encryption(key, rounds); 
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
            if (value.Length >= 256) throw new InvalidKeyException();

		    // вернуть алгоритм расшифрования блока данных
		    return new Decryption(key, rounds); 
		}
	    ///////////////////////////////////////////////////////////////////////////
	    // Алгоритм зашифрования блока
	    ///////////////////////////////////////////////////////////////////////////
	    public class Encryption : BlockTransform
	    {
		    // расписание ключей и число раундов
		    private ulong[] keys; private int rounds; 
        
		    // Конструктор
		    public Encryption(ISecretKey key, int rounds) : base(16)
		    { 
                // проверить тип ключа
                this.rounds = rounds; if (key.Value == null) 
                {
                    // при ошибке выбросить исключение
                    throw new InvalidKeyException();
                }
                // создать расписание ключей
                keys = GetKeys(key.Value, rounds); 
		    }
		    // обработка одного блока данных
		    protected override void Update(byte[] src, int srcOff, byte[] dest, int destOff)
		    {
                ulong A = Math.Convert.ToUInt64(src, srcOff + 0, Endian) + keys[0];
                ulong B = Math.Convert.ToUInt64(src, srcOff + 8, Endian) + keys[1];

                for (int i = 1; i <= rounds; i++)
                {
                    A = RotateLeft(A ^ B, B) + keys[2 * i + 0];
                    B = RotateLeft(B ^ A, A) + keys[2 * i + 1];
                }
                Math.Convert.FromUInt64(A, Endian, dest, destOff + 0);
                Math.Convert.FromUInt64(B, Endian, dest, destOff + 8);
            }
	    }
	    ///////////////////////////////////////////////////////////////////////////
	    // Алгоритм расшифрования блока
	    ///////////////////////////////////////////////////////////////////////////
	    public class Decryption : BlockTransform
	    {
		    // расписание ключей и число раундов
		    private ulong[] keys; private  int rounds; 

		    // Конструктор
		    public Decryption(ISecretKey key, int rounds) : base(16)
		    { 
                // проверить тип ключа
                this.rounds = rounds; if (key.Value == null) 
                {
                    // при ошибке выбросить исключение
                    throw new InvalidKeyException();
                }
                // создать расписание ключей
                keys = GetKeys(key.Value, rounds); 
		    }
		    // обработка одного блока данных
		    protected override void Update(byte[] src, int srcOff, byte[] dest, int destOff)
		    {
                ulong A = Math.Convert.ToUInt64(src, srcOff + 0, Endian);
                ulong B = Math.Convert.ToUInt64(src, srcOff + 8, Endian);

                for (int i = rounds; i >= 1; i--)
                {
                    B = RotateRight(B - keys[2 * i + 1], A) ^ A;
                    A = RotateRight(A - keys[2 * i + 0], B) ^ B;
                }
                Math.Convert.FromUInt64(A - keys[0], Endian, dest, destOff + 0);
                Math.Convert.FromUInt64(B - keys[1], Endian, dest, destOff + 8);
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
        private const ulong P64 = 0xb7e151628aed2a6bL;
        private const ulong Q64 = 0x9e3779b97f4a7c15L;

        private static ulong RotateLeft(ulong x, ulong y)
        {
            return ((x << (int)(y & 0x3F)) | (x >> (64 - (int)(y & 0x3F))));
        }
        private static ulong RotateRight(ulong x, ulong y)
        {
            return ((x >> (int)(y & 0x3F)) | (x << (64 - (int)(y & 0x3F))));
        }
	    ///////////////////////////////////////////////////////////////////////////
	    // Создать расписание ключей
	    ///////////////////////////////////////////////////////////////////////////
        private static ulong[] GetKeys(byte[] key, int rounds)
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
            ulong[] L = new ulong[(key.Length + 7) / 8];

            for (int i = 0; i < key.Length; i++)
            {
                L[i / 8] += (ulong)key[i] << (8 * (i % 8));
            }
            //
            // Phase 2:
            //   Initialize S to a particular fixed pseudo-random bit pattern
            //   using an arithmetic progression modulo 2^wordsize determined
            //   by the magic numbers, Pw & Qw.
            //
            ulong[] S = new ulong[2 * (rounds + 1)]; S[0] = P64;
        
            for (int i = 1; i < S.Length; i++) S[i] = S[i - 1] + Q64;
            //
            // Phase 3:
            //   Mix in the user's secret key in 3 passes over the arrays S & L.
            //   The max of the arrays sizes is used as the loop control
            //
            int iter = (L.Length > S.Length) ? 3 * L.Length : 3 * S.Length;

            ulong A = 0; ulong B = 0; 
            for (int i = 0, j = 0, k = 0; k < iter; k++)
            {
                A = S[i] = RotateLeft(S[i] + A + B,     3);
                B = L[j] = RotateLeft(L[j] + A + B, A + B);
            
                i = (i + 1) %  S.Length;
                j = (j + 1) %  L.Length;
            }
            return S; 
        }
    }
}
