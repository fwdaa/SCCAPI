using System;

namespace Aladdin.CAPI.PBE
{
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм наследования ключа PBKDF1
	///////////////////////////////////////////////////////////////////////////
    public class PBKDF1 : KeyDerive
	{
		private Hash   hashAlgorithm; 	// алгоритм хэширования
		private byte[] salt; 			// salt-значение
		private int	   iterations;		// число итераций

		// конструктор
		public PBKDF1(Hash hashAlgorithm, byte[] salt, int iterations)
		{ 
            // сохранить переданные параметры
			this.hashAlgorithm = RefObject.AddRef(hashAlgorithm);	

            // сохранить переданные параметры
			this.salt = salt; this.iterations = iterations;
        }
        // освободить выделенные ресурсы
        protected override void OnDispose()
        {
            // освободить выделенные ресурсы
            RefObject.Release(hashAlgorithm); base.OnDispose();
        }
		// наследовать ключ
		public override ISecretKey DeriveKey(ISecretKey password, 
            byte[] iv, SecretKeyFactory keyFactory, int deriveSize)
		{
            // проверить наличие буфера для синхропосылки
            if (iv == null) iv = new byte[0]; 

			// проверить тип ключа
			if (password.Value == null) throw new InvalidKeyException();

			// проверить корректность параметров
			if (deriveSize + iv.Length > hashAlgorithm.HashSize) 
            {
                // при ошибке выбросить исключение
                throw new InvalidKeyException();
            }
			// объединить пароль и salt-значение 
			byte[] pass_salt = Arrays.Concat(password.Value, salt); 

			// вычислить хэш-значение от объединения
			byte[] hash = hashAlgorithm.HashData(pass_salt, 0, pass_salt.Length); 

			// для всех итераций
			for (int i = 1; i < iterations; i++)
			{
				// вычислить хэш-значение от хэш-значения
				hash = hashAlgorithm.HashData(hash, 0, hash.Length); 
			}
		    // извлечь ключ
            byte[] key = new byte[deriveSize]; Array.Copy(hash, 0, key, 0, key.Length);

            // извлечь вектор инициализации
            Array.Copy(hash, key.Length, iv, 0, iv.Length); return keyFactory.Create(key); 
 		}
	}
}
