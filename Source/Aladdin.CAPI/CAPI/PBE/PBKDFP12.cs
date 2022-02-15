using System;
using System.Text;

namespace Aladdin.CAPI.PBE
{
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм наследования ключа PBKDF PKCS12
	///////////////////////////////////////////////////////////////////////////
    public class PBKDFP12 : KeyDerive
	{
		private Hash   hashAlgorithm; 	// алгоритм хэширования
		private byte[] salt; 			// salt-значение
		private int	   iterations;		// число итераций
		private byte   id;				// идентификатор типа

		// конструктор 
		public PBKDFP12(Hash hashAlgorithm, byte[] salt, int iterations, byte id)
		{ 
            // сохранить переданные параметры
			this.hashAlgorithm = RefObject.AddRef(hashAlgorithm);

            // сохранить переданные параметры
			this.salt = salt; this.iterations = iterations; this.id = id;
	    }  
        // освободить выделенные ресурсы
        protected override void OnDispose() 
        { 
            // освободить выделенные ресурсы
            RefObject.Release(hashAlgorithm); base.OnDispose();
        } 
		// наследовать ключ
		public override ISecretKey DeriveKey(ISecretKey password, 
            byte[] random, SecretKeyFactory keyFactory, int deriveSize)
		{
            // при наличии пароля
            byte[] pswd = null; if (password != null)
            { 
                // раскодировать значение пароля
                string value = Encoding.UTF8.GetString(password.Value); 

                // выделить память для кодирования
                pswd = new byte[(value.Length + 1) * 2];

                // для всех символов
                for (int i = 0; i < value.Length; i ++)
                {
                    // получить код символа
                    int code = Char.ConvertToUtf32(value, i); 

                    // закодировать символы
                    pswd[i * 2 + 0] = (byte)(code >> 8);
                    pswd[i * 2 + 1] = (byte)(code     );
                }
            }
			// определить размер хэш-значения и блока
			int u = hashAlgorithm.HashSize; int v = hashAlgorithm.BlockSize; 

			// выделить память для ключа
			byte[] key = new byte[deriveSize]; byte[] D = new byte[v]; 
			
			// расширить идентификатор до размера блока
			for (int i = 0; i < D.Length; i++) D[i] = id;

			// инициализировать расширение salt-значения и пароля
			byte[] S = new byte[0]; byte[] P = new byte[0];

			// при наличии salt-значения
			if (salt != null && salt.Length > 0)
			{
				// выделить память для расширения salt-значения
				S = new byte[v * ((salt.Length + v - 1) / v)];

				// расширить salt-значение 
				for (int i = 0; i < S.Length; i++) S[i] = salt[i % salt.Length];
			}
			// при наличии пароля
			if (pswd != null && pswd.Length > 0)
			{
				// выделить память для расширения пароля
				P = new byte[v * ((pswd.Length + v - 1) / v)];

				// расширить пароль
				for (int i = 0; i < P.Length; i++) P[i] = pswd[i % pswd.Length];
			}
			// объединить расширение salt-значения и пароля
			byte[] I = Arrays.Concat(S, P); 

			// для всех частей генерируемого ключа
			for (int i = 1; i <= (deriveSize + u - 1) / u; i++)
			{
				// выделить память для хэш-значения
				byte[] A = new byte[u]; byte[] B = new byte[v];

				// получить хэш-значение от расширений
				hashAlgorithm.Init(); 
				hashAlgorithm.Update(D, 0, D.Length);
				hashAlgorithm.Update(I, 0, I.Length);
				hashAlgorithm.Finish(A, 0);

				// для всех итераций
				for (int j = 1; j < iterations; j++)
				{
					// вычислить хэш-значение от хэш-значения 
					hashAlgorithm.Init(); 
					hashAlgorithm.Update(A, 0, A.Length);
					hashAlgorithm.Finish(A, 0);
				}
				// расширить/сузить хэш-значение до размера блока
				for (int j = 0; j < B.Length; j++) B[j] = A[j % A.Length];

				// для каждого блока объединения
				for (int j = 0; j < I.Length; j += v) 
				{
					// увеличить младший байт блока на единицу
					int x = (B[B.Length - 1] & 0xff) + (I[j + B.Length - 1] & 0xff) + 1;

					// увеличить младший байт блока на единицу
					I[j + B.Length - 1] = (byte)x; x >>= 8;

					// для старших байтов блока
					for (int k = B.Length - 2; k >= 0; k--)
					{
						// учесть байт переноса при сложении
						x += (B[k] & 0xff) + (I[j + k] & 0xff);

						// учесть байт переноса при сложении
						I[j + k] = (byte)x; x >>= 8;
					}
				}
				// для последней части ключа
				if (A.Length > key.Length - (i - 1) * u)
				{
					// извлечь последнюю часть ключа
					Array.Copy(A, 0, key, (i - 1) * u, key.Length - (i - 1) * u);
				}
				// извлечь непоследнюю часть ключа
				else Array.Copy(A, 0, key, (i - 1) * u, A.Length);
			}
			return keyFactory.Create(key);
		}
	}
}
