using System; 

namespace Aladdin.CAPI.PBE
{
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм шифрования по паролю PKCS12
	///////////////////////////////////////////////////////////////////////////
	public class PBESP12 : Cipher
	{
		// используемые алгоритмы наследования
        private KeyDerive keyDerive; private KeyDerive ivDerive; 
        // алгоритм шифрования и размер ключа
        private IAlgorithm cipher; private SecretKeyFactory keyFactory; private int keyLength; 

		// конструктор 
		public PBESP12(IBlockCipher cipher, int keyLength, Hash hashAlgorithm, byte[] salt, int iterations)
		{
            // сохранить переданные параметры
            this.keyFactory = cipher.KeyFactory; this.keyLength = keyLength; 

            // сохранить переданные параметры
            this.cipher = RefObject.AddRef(cipher); 

			// создать алгоритм наследования ключа
			keyDerive = new PBKDFP12(hashAlgorithm, salt, iterations, 1); 

			// создать алгоритм наследования вектора инициализации
			ivDerive = new PBKDFP12(hashAlgorithm, salt, iterations, 2); 
		}
		// конструктор 
		public PBESP12(Cipher cipher, int keyLength, Hash hashAlgorithm, byte[] salt, int iterations)
		{
            // сохранить переданные параметры
            this.keyFactory = cipher.KeyFactory; this.keyLength = keyLength; 

            // сохранить переданные параметры
            this.cipher = RefObject.AddRef(cipher); 

			// создать алгоритм наследования ключа
			keyDerive = new PBKDFP12(hashAlgorithm, salt, iterations, 1); 

			// создать алгоритм наследования вектора инициализации
			ivDerive = new PBKDFP12(hashAlgorithm, salt, iterations, 2); 
		}
        // освободить выделенные ресурсы
        protected override void OnDispose() 
        { 
            // освободить выделенные ресурсы
            RefObject.Release(cipher);

            // освободить выделенные ресурсы
            ivDerive.Dispose(); keyDerive.Dispose(); base.OnDispose();
        } 
        // размер блока алгоритма
	    public override int BlockSize { get { 

            // вернуть размер блока алгоритма
            if (cipher is Cipher) return ((Cipher)cipher).BlockSize; 
            
            // вернуть размер блока алгоритма
            else return ((IBlockCipher)cipher).BlockSize; 
        }}
		// создать алгоритм шифрования
		protected virtual Cipher CreateCipher(byte[] iv)
        {
            // проверить тип алгоритма
            if (cipher is Cipher) return RefObject.AddRef((Cipher)cipher); 
            else {
                // указать режим блочного алгоритма
                CipherMode parameters = new CipherMode.CBC(iv);
        
                // получить алгоритм шифрования
                Cipher mode = ((IBlockCipher)cipher).CreateBlockMode(parameters); 
        
                // проверить наличие алгоритма
                if (mode == null) throw new NotSupportedException(); return mode;  
            }
        }
		// алгоритм зашифрования данных
		protected override Transform CreateEncryption(ISecretKey password)
		{
			// наследовать ключ по паролю
			using (ISecretKey key = keyDerive.DeriveKey(password, null, keyFactory, keyLength))
            { 
 			    // наследовать вектор инициализации 
			    using (ISecretKey iv = ivDerive.DeriveKey(password, null, SecretKeyFactory.Generic, BlockSize))
                {
			        // проверить тип ключа
			        if (iv.Value == null) throw new InvalidKeyException();
 
                    // создать алгоритм шифрования
                    using (Cipher cipher = CreateCipher(iv.Value))
                    {
                        // вернуть преобразование зашифрования
                        return cipher.CreateEncryption(key, PaddingMode.PKCS5);
                    }
                }
            }
		}
		// алгоритм расшифрования данных
		protected override Transform CreateDecryption(ISecretKey password)
		{
			// наследовать ключ по паролю
			using (ISecretKey key = keyDerive.DeriveKey(password, null, keyFactory, keyLength))
            { 
 			    // наследовать вектор инициализации 
			    using (ISecretKey iv = ivDerive.DeriveKey(password, null, SecretKeyFactory.Generic, BlockSize))
                {
			        // проверить тип ключа
			        if (iv.Value == null) throw new InvalidKeyException();
 
                    // создать алгоритм шифрования
                    using (Cipher cipher = CreateCipher(iv.Value))
                    {
			            // вернуть преобразование расшифрования
			            return cipher.CreateDecryption(key, PaddingMode.PKCS5); 
                    }
                }
            }
		}
	}
}
