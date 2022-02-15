package aladdin.capi.pbe;
import aladdin.*; 
import aladdin.capi.*;
import aladdin.util.*; 
import java.security.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Алгоритм наследования ключа PBKDF PKCS12
///////////////////////////////////////////////////////////////////////////
public class PBKDFP12 extends KeyDerive
{
	private final Hash   hashAlgorithm; // алгоритм хэширования
	private final byte[]  salt; 		 // salt-значение
	private final int	  iterations;	 // число итераций
	private final byte    id;			 // идентификатор типа

	// конструктор 
	public PBKDFP12(Hash hashAlgorithm, byte[] salt, int iterations, byte id) 
	{ 
        // сохранить переданные параметры
		this.hashAlgorithm	= RefObject.addRef(hashAlgorithm);
        
        // сохранить переданные параметры
		this.salt = salt; this.iterations = iterations; this.id = id;
	}  
    // освободить выделенные ресурсы
    @Override protected void onClose() throws IOException 
    { 
        // освободить выделенные ресурсы
        RefObject.release(hashAlgorithm); super.onClose();
    } 
	// наследовать ключ
	@Override public ISecretKey deriveKey(ISecretKey password, 
        byte[] random, SecretKeyFactory keyFactory, int keySize) 
            throws IOException, InvalidKeyException
	{
        // при наличии пароля
        byte[] pswd = null; if (password != null)
        {
            // получить закодированное представление
            byte[] encoded = password.value(); 
        
            // проверить наличие значения
            if (encoded == null) throw new InvalidKeyException(); 
            try { 
                // раскодировать значение пароля
                String value = new String(encoded, "UTF-8"); 

                // выделить память для кодирования
                pswd = new byte[(value.length() + 1) * 2];

                // для всех символов
                for (int i = 0; i < value.length(); i ++)
                {
                    // закодировать символы
                    pswd[i * 2 + 0] = (byte)(value.codePointAt(i) >>> 8);
                    pswd[i * 2 + 1] = (byte)(value.codePointAt(i)      );
                }
            }
            // обработать неожидаемое исключение
            catch (UnsupportedEncodingException e) { throw new RuntimeException(e); }
        }
		// определить размер хэш-значения и блока
		int u = hashAlgorithm.hashSize(); int v = hashAlgorithm.blockSize(); 

		// выделить память для ключа
		byte[] key = new byte[keySize]; byte[] D = new byte[v]; 
			
		// расширить идентификатор до размера блока
		for (int i = 0; i < D.length; i++) D[i] = id;

		// инициализировать расширение salt-значения и пароля
		byte[] S = new byte[0]; byte[] P = new byte[0];

		// при наличии salt-значения
		if (salt != null && salt.length > 0)
		{
			// выделить память для расширения salt-значения
			S = new byte[v * ((salt.length + v - 1) / v)];

			// расширить salt-значение 
			for (int i = 0; i < S.length; i++) S[i] = salt[i % salt.length];
		}
		// при наличии пароля
		if (pswd != null && pswd.length > 0)
		{
			// выделить память для расширения пароля
			P = new byte[v * ((pswd.length + v - 1) / v)];

			// расширить пароль
			for (int i = 0; i < P.length; i++) P[i] = pswd[i % pswd.length];
		}
		// объединить расширение salt-значения и пароля
		byte[] I = Array.concat(S, P); 

		// для всех частей генерируемого ключа
		for (int i = 1; i <= (keySize + u - 1) / u; i++)
		{
			// выделить память для хэш-значения
			byte[] A = new byte[u]; byte[] B = new byte[v];

			// получить хэш-значение от расширений
			hashAlgorithm.init(); 
			hashAlgorithm.update(D, 0, D.length);
			hashAlgorithm.update(I, 0, I.length);
			hashAlgorithm.finish(A, 0);

			// для всех итераций
			for (int j = 1; j < iterations; j++)
			{
				// вычислить хэш-значение от хэш-значения 
				hashAlgorithm.init(); 
				hashAlgorithm.update(A, 0, A.length);
				hashAlgorithm.finish(A, 0);
			}
			// расширить/сузить хэш-значение до размера блока
			for (int j = 0; j < B.length; j++) B[j] = A[j % A.length];
            
			// для каждого блока объединения
			for (int j = 0; j < I.length; j += v) 
			{
				// увеличить младший байт блока на единицу
				int x = (B[B.length - 1] & 0xff) + (I[j + B.length - 1] & 0xff) + 1;

				// увеличить младший байт блока на единицу
				I[j + B.length - 1] = (byte)x; x >>>= 8;

				// для старших байтов блока
				for (int k = B.length - 2; k >= 0; k--)
                {
					// учесть байт переноса при сложении
					x += (B[k] & 0xff) + (I[j + k] & 0xff);

					// учесть байт переноса при сложении
					I[j + k] = (byte)x; x >>>= 8;
				}
			}
			// для последней части ключа
			if (A.length > key.length - (i - 1) * u)
			{
				// извлечь последнюю часть ключа
				System.arraycopy(A, 0, key, (i - 1) * u, key.length - (i - 1) * u);
			}
			// извлечь непоследнюю часть ключа
			else System.arraycopy(A, 0, key, (i - 1) * u, A.length);
		}
        // вернуть ключ
		return keyFactory.create(key);
	}
}
