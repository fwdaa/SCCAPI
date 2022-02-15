using System;

namespace Aladdin.CAPI.PBE
{
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм шифрования по паролю PBES1
	///////////////////////////////////////////////////////////////////////////
    public abstract class PBES1 : Cipher
	{
		// алгоритм псевдослучайной генерации
		private KeyDerive algorithm; private SecretKeyFactory keyFactory; 

		// конструктор 
		protected PBES1(Hash hashAlgorithm, byte[] salt, int iterations, SecretKeyFactory keyFactory)
		{
			// создать алгоритм наследования ключа
			algorithm = new PBKDF1(hashAlgorithm, salt, iterations); this.keyFactory = keyFactory;
		}
        // освободить выделенные ресурсы
        protected override void OnDispose()
        {
            // освободить выделенные ресурсы
            algorithm.Dispose(); base.OnDispose();
        }
        // размер блока алгоритма
	    public override int BlockSize { get { return IVLength; }}

		// создать алгоритм шифрования
		protected abstract Cipher CreateCipher(byte[] iv); 

		// размер ключа и вектора инициализации
		protected abstract int KeyLength { get; } 
		protected abstract int IVLength	 { get; } 

		// алгоритм зашифрования данных
		protected override Transform CreateEncryption(ISecretKey password)
		{
            // выделить память для синхропосылки
            byte[] iv = new byte[IVLength > 1 ? IVLength : 0];  

			// наследовать ключ и вектор инициализации по паролю
			using (ISecretKey key = algorithm.DeriveKey(password, iv, keyFactory, KeyLength))
			{
                // создать алгоритм шифрования
                using (Cipher cipher = CreateCipher(iv))
                {
                    // вернуть преобразование зашифрования
                    return cipher.CreateEncryption(key, PaddingMode.PKCS5); 
                }
			}
		}
		// алгоритм расшифрования данных
		protected override Transform CreateDecryption(ISecretKey password)
		{
            // выделить память для синхропосылки
            byte[] iv = new byte[IVLength > 1 ? IVLength : 0];  

			// наследовать ключ и вектор инициализации по паролю
			using (ISecretKey key = algorithm.DeriveKey(password, iv, keyFactory, KeyLength))
			{
                // создать алгоритм шифрования
                using (Cipher cipher = CreateCipher(iv))
                {
                    // вернуть преобразование расшифрования
                    return cipher.CreateDecryption(key, PaddingMode.PKCS5); 
                }
			}
		}
	}
}
