using System;
using System.Diagnostics.CodeAnalysis; 

namespace Aladdin.CAPI
{
    ///////////////////////////////////////////////////////////////////////////
	// Симметричный алгоритм шифрования
    ///////////////////////////////////////////////////////////////////////////
    [SuppressMessage("Microsoft.Design", "CA1063:ImplementIDisposableCorrectly")]
	public class Cipher : RefObject, IAlgorithm
	{
        // тип ключа
        public virtual SecretKeyFactory KeyFactory  { get { return SecretKeyFactory.Generic; }}
	    // размер блока
	    public virtual int BlockSize { get { return 1; }} 
        
        // режим алгоритма
	    public virtual CipherMode Mode { get { return null; }}

	    // зашифровать данные
	    public int Encrypt(ISecretKey key, PaddingMode padding, 
            byte[] data, int dataOff, int dataLen, byte[] buf, int bufOff) 
	    {
            // установить ключ алгоритма
            using (Transform encryption = CreateEncryption(key, padding))
            {
                // зашифровать данные
                return encryption.TransformData(data, dataOff, dataLen, buf, bufOff); 
            }
	    }
		// зашифровать данные
		public byte[] Encrypt(ISecretKey key, PaddingMode padding, 
            byte[] data, int dataOff, int dataLen)
		{
			// установить ключ алгоритма
			using (Transform encryption = CreateEncryption(key, padding))
            { 
			    // зашифровать данные
			    return encryption.TransformData(data, dataOff, dataLen); 
            }
		}
	    // расшифровать данные
	    public int Decrypt(ISecretKey key, PaddingMode padding, 
            byte[] data, int dataOff, int dataLen, byte[] buf, int bufOff) 
	    {
		    // установить ключ алгоритма
		    using (Transform decryption = CreateDecryption(key, padding))
            {
                // расшифровать данные
                return decryption.TransformData(data, dataOff, dataLen, buf, bufOff); 
            }
        }
		// расшифровать данные
		public byte[] Decrypt(ISecretKey key, PaddingMode padding, 
            byte[] data, int dataOff, int dataLen)
		{
			// установить ключ алгоритма
			using (Transform decryption = CreateDecryption(key, padding))
            { 
			    // расшифровать данные
			    return decryption.TransformData(data, dataOff, dataLen);
            }
		}
		// алгоритм зашифрования данных
		public virtual Transform CreateEncryption(ISecretKey key, PaddingMode padding)
        {
   		    // получить режим зашифрования 
		    return CreateEncryption(key); 
        }
		// алгоритм расшифрования данных
		public virtual Transform CreateDecryption(ISecretKey key, PaddingMode padding)
        {
   		    // получить режим расшифрования 
		    return CreateDecryption(key); 
        }
        // переопределяемые функции
        protected virtual Transform CreateEncryption(ISecretKey key) { return new Transform(); }
        protected virtual Transform CreateDecryption(ISecretKey key) { return new Transform(); }

        // создать алгоритм шифрования ключа
        public virtual CAPI.KeyWrap CreateKeyWrap(PaddingMode padding)
        {
            // создать алгоритм зашифрования ключа
            return new KeyWrap(this, padding); 
        }
	    ///////////////////////////////////////////////////////////////////////////
	    // Алгоритм шифрования ключа на основе алгоритма шифрования
	    ///////////////////////////////////////////////////////////////////////////
	    private class KeyWrap : CAPI.KeyWrap
	    {
            // используемый алгоритм шифрования и способ дополнения блока
            private Cipher cipher; private PaddingMode padding; 
    
		    // конструктор
		    public KeyWrap(Cipher cipher, PaddingMode padding)
		    {
			    // сохранить переданные параметры
			     this.cipher = RefObject.AddRef(cipher); this.padding = padding; 
            } 
            // освободить выделенные ресурсы
            protected override void OnDispose() 
            { 
                // освободить выделенные ресурсы
                RefObject.Release(cipher); base.OnDispose();
            }
		    // тип ключа
		    public override SecretKeyFactory KeyFactory { get { return cipher.KeyFactory; }} 

		    // зашифровать ключ
		    public override byte[] Wrap(IRand rand, ISecretKey key, ISecretKey CEK)
		    {
			    // проверить тип ключа
			    if (CEK.Value == null) throw new InvalidKeyException();

			    // зашифровать ключ
			    return cipher.Encrypt(key, padding, CEK.Value, 0, CEK.Length); 
		    }
		    // расшифровать ключ
		    public override ISecretKey Unwrap(ISecretKey key, 
                byte[] wrappedCEK, SecretKeyFactory keyFactory)
		    {
			    // расшифровать ключ
			    return keyFactory.Create(cipher.Decrypt(
                    key, padding, wrappedCEK, 0, wrappedCEK.Length
                )); 
		    }
        }
        ////////////////////////////////////////////////////////////////////////////
        // Тест известного ответа
        ////////////////////////////////////////////////////////////////////////////
        public static void KnownTest(Cipher cipher, 
            PaddingMode padding, byte[] key, byte[] plaintext, byte[] ciphertext)
        {
            // вывести параметры алгоритмов
            if (cipher.Mode != null) cipher.Mode.Dump();

            // указать используемый ключ
            using (ISecretKey k = cipher.KeyFactory.Create(key))
            {
                // вывести сообщение
                Test.Dump("Key", k.Value); Test.Dump("Data", plaintext);

                // зашифровать данные
                byte[] result = cipher.Encrypt(k, padding, plaintext, 0, plaintext.Length); 

                // вывести сообщение
                Test.Dump("Required", ciphertext); Test.Dump("Encrypted", result); 

                // проверить совпадение результата
                if (ciphertext != null && !Arrays.Equals(result, ciphertext)) 
                {
                    // при ошибке выбросить исключение
                    throw new ArgumentException(); 
                }
                // расшифровать данные
                result = cipher.Decrypt(k, padding, result, 0, result.Length);

                // вывести сообщение
                Test.Dump("Decrypted", result); 

                // проверить совпадение результата
                if (!Arrays.Equals(result, plaintext)) throw new ArgumentException(); 

                // вывести сообщение
                Test.WriteLine("OK"); Test.WriteLine();
            }
        }
        ////////////////////////////////////////////////////////////////////////////
        // Тест сравнения
        ////////////////////////////////////////////////////////////////////////////
        public static void CompatibleTest(IRand rand, Cipher cipherAlgorithm, 
            Cipher trustAlgorithm, PaddingMode padding, int[] dataSizes) 
        {
            // получить допустимые размеры ключей
            int[] keySizes = cipherAlgorithm.KeyFactory.KeySizes; 
        
            // при отсутствии ограничений на размер ключа
            if (keySizes == KeySizes.Unrestricted || keySizes.Length > 32)
            {
                // скорректировать допустимые размеры ключей
                keySizes = new int[] { 0, 8, 16, 24, 32, 64 }; 
            }
            // для всех размеров ключей
            foreach (int keySize in keySizes)
            { 
                // проверить поддержку размера ключа
                if (!KeySizes.Contains(cipherAlgorithm.KeyFactory.KeySizes, keySize)) continue; 

                // сгенерировать ключ 
                using (ISecretKey key = cipherAlgorithm.KeyFactory.Generate(rand, keySize)) 
                {
                    // для всех требуемых размеров
                    for (int i = 0; i < dataSizes.Length; i++)
                    {
                        // сгенерировать случайные данные
                        byte[] data = new byte[dataSizes[i]]; rand.Generate(data, 0, data.Length);
                    
                        // вывести параметры алгоритмов
                        if (cipherAlgorithm.Mode != null) cipherAlgorithm.Mode.Dump();

                        // вывести сообщение
                        Test.Dump("Key", key.Value); Test.Dump("Data", data, 0, data.Length); 

                        // зашифровать данные
                        byte[] encrypted1 = cipherAlgorithm.Encrypt(key, padding, data, 0, data.Length); 
                        byte[] encrypted2 = trustAlgorithm .Encrypt(key, padding, data, 0, data.Length); 
        
                        // вывести сообщение
                        Test.Dump("Encrypted1", encrypted1); Test.Dump("Encrypted2", encrypted2); 

                        // проверить совпадение шифртекста
                        if (!Arrays.Equals(encrypted1, encrypted2)) throw new ArgumentException(); 

                        // расшифровать данные
                        byte[] decrypted = cipherAlgorithm.Decrypt(
                            key, padding, encrypted1, 0, encrypted1.Length
                        ); 
                        // проверить совпадение результатов
                        if (!Arrays.Equals(decrypted, data)) throw new ArgumentException(); 

                        // вывести сообщение
                        Test.WriteLine("OK"); Test.WriteLine();
                    }
                }
            }
        }
	}
}

