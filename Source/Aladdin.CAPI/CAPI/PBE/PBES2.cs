using System;

namespace Aladdin.CAPI.PBE
{
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм шифрования по паролю PBES2
	///////////////////////////////////////////////////////////////////////////
    public class PBES2 : Cipher
	{
		private KeyDerive derivationAlgorithm;  // алгоритм наследования
		private Cipher    cipherAlgorithm;	    // алгоритм шифрования

        // создать алгоритм
        public static PBES2 Сreate(Factory factory, 
            SecurityStore scope, ASN1.ISO.PKCS.PKCS5.PBES2Parameter pbeParameters)
        {
            // создать алгоритм шифрования
            using (Cipher cipher = factory.CreateAlgorithm<Cipher>(
                scope, pbeParameters.EncryptionScheme))
            {
                // проверить наличие алгоритма
                if (cipher == null) return null; 
                    
                // создать алгоритм наследования ключа по паролю
                using (KeyDerive derivationAlgorithm = factory.CreateAlgorithm<KeyDerive>(
                    scope, pbeParameters.KeyDerivationFunc))
                {
                    // проверить наличие алгоритма
                    if (derivationAlgorithm == null) return null; 
                 
                    // создать алгоритм шифрования по паролю
                    return new PBES2(derivationAlgorithm, cipher);  
                }
            }
        }
		// конструктор 
		public PBES2(KeyDerive derivationAlgorithm, Cipher cipherAlgorithm)
		{
            // сохранить переданные параметры
			this.derivationAlgorithm = RefObject.AddRef(derivationAlgorithm);
			this.cipherAlgorithm	 = RefObject.AddRef(cipherAlgorithm);	
		}
        // освободить выделенные ресурсы
        protected override void OnDispose()
        {
            // освободить выделенные ресурсы
            RefObject.Release(derivationAlgorithm); 
                
            // освободить выделенные ресурсы
            RefObject.Release(cipherAlgorithm); base.OnDispose();
        }
        // размер блока алгоритма
        public override int BlockSize { get { return cipherAlgorithm.BlockSize; }}

		// алгоритм зашифрования данных
		protected override Transform CreateEncryption(ISecretKey password)
		{
            // определить тип ключа
            SecretKeyFactory keyFactory = cipherAlgorithm.KeyFactory; int keySize = -1; 

            // определить допустимые размеры ключей
            int[] keySizes = cipherAlgorithm.KeyFactory.KeySizes; 
        
            // указать рекомендуемый размер ключа
            if (keySizes != null && keySizes.Length == 1) keySize = keySizes[0]; 
        
			// наследовать ключ по паролю
			using (ISecretKey key = derivationAlgorithm.DeriveKey(password, null, keyFactory, keySize))
            { 
                // проверить допустимость размера ключа
                if (!CAPI.KeySizes.Contains(keySizes, key.Length)) 
                {
                    // выбросить исключение
                    throw new InvalidOperationException();
                }
 			    // вернуть преобразование зашифрования
			    return cipherAlgorithm.CreateEncryption(key, PaddingMode.PKCS5); 
            }
		}
		// алгоритм расшифрования данных
		protected override Transform CreateDecryption(ISecretKey password)
		{
            // определить тип ключа
            SecretKeyFactory keyFactory = cipherAlgorithm.KeyFactory; int keySize = -1; 

            // определить допустимые размеры ключей
            int[] keySizes = cipherAlgorithm.KeyFactory.KeySizes; 
        
            // указать рекомендуемый размер ключа
            if (keySizes != null && keySizes.Length == 1) keySize = keySizes[0]; 

			// наследовать ключ по паролю
			using (ISecretKey key = derivationAlgorithm.DeriveKey(password, null, keyFactory, keySize))
            { 
                // проверить допустимость размера ключа
                if (!CAPI.KeySizes.Contains(keySizes, key.Length)) 
                {
                    // выбросить исключение
                    throw new InvalidOperationException();
                }
 			    // вернуть преобразование расшифрования
			    return cipherAlgorithm.CreateDecryption(key, PaddingMode.PKCS5);
            } 
		}
	}
}
