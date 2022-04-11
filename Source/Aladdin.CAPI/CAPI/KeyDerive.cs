using System; 
using System.Diagnostics.CodeAnalysis; 

namespace Aladdin.CAPI
{
    ///////////////////////////////////////////////////////////////////////////
	// Алгоритм наследования ключа
    ///////////////////////////////////////////////////////////////////////////
    [SuppressMessage("Microsoft.Design", "CA1063:ImplementIDisposableCorrectly")]
    public abstract class KeyDerive : RefObject, IAlgorithm
    {
        // тип ключа
        public virtual SecretKeyFactory KeyFactory  { get { return SecretKeyFactory.Generic; }}

		// наследовать ключ
		public abstract ISecretKey DeriveKey(ISecretKey key, 
            byte[] random, SecretKeyFactory keyFactory, int deriveSize
        ); 
        ////////////////////////////////////////////////////////////////////////////
        // Тест известного ответа
        ////////////////////////////////////////////////////////////////////////////
        public static void KnownTest(KeyDerive kdfAlgorithm, 
            byte[] keyValue, byte[] data, byte[] check)
        {
            // указать фабрику кодирования ключей
            SecretKeyFactory keyFactory = SecretKeyFactory.Generic; 

            // указать используемый ключ
            using (ISecretKey key = kdfAlgorithm.KeyFactory.Create(keyValue))
            {
                // вывести сообщение
                Test.Dump("Key", key.Value); Test.Dump("Data", data); 

                // создать ключ для сравнения
                using (ISecretKey checkKey = keyFactory.Create(check))
                {
                    // вывести сообщение
                    Test.Dump("Required", checkKey.Value); 
            
                    // наследовать ключ
                    using (ISecretKey result = kdfAlgorithm.DeriveKey(
                        key, data, keyFactory, check.Length))
                    { 
                        // вывести сообщение
                        Test.Dump("Derived", result.Value); 
            
                        // проверить совпадение
                        if (!Arrays.Equals(result.Value, checkKey.Value)) 
                        {
                            // при ошибке выбросить исключение
                            throw new ArgumentException(); 
                        }
                    }
                    // вывести сообщение
                    Test.WriteLine("OK"); Test.WriteLine();
                }
            }
        }
        ////////////////////////////////////////////////////////////////////////////
        // Тест сравнения
        ////////////////////////////////////////////////////////////////////////////
        public static void CompatibleTest(IRand rand, KeyDerive kdfAlgorithm, 
            KeyDerive trustAlgorithm, byte[] data, int deriveSize) 
        {
            // указать фабрику кодирования ключей
            SecretKeyFactory keyFactory = SecretKeyFactory.Generic; 

            // получить допустимые размеры ключей
            int[] keySizes = kdfAlgorithm.KeyFactory.KeySizes; 
        
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
                if (!KeySizes.Contains(kdfAlgorithm.KeyFactory.KeySizes, keySize)) continue; 
            
                // сгенерировать ключ 
                using (ISecretKey key = kdfAlgorithm.KeyFactory.Generate(rand, keySize))
                {
                    // вывести сообщение
                    Test.Dump("Key" , key.Value); Test.Dump("Data", data); 

                    // наследовать ключ
                    using (ISecretKey key1 = kdfAlgorithm.DeriveKey(key, data, keyFactory, deriveSize))
                    {
                        // наследовать ключ
                        using (ISecretKey key2 = trustAlgorithm.DeriveKey(key, data, keyFactory, deriveSize)) 
                        {
                            // вывести сообщение
                            Test.Dump("Derived1", key1.Value); 
                            Test.Dump("Derived2", key2.Value); 

                            // проверить совпадение ключей
                            if (!Arrays.Equals(key1.Value, key2.Value)) throw new ArgumentException(); 
                        }
                    }
                }
            }
            // вывести сообщение
            Test.WriteLine("OK"); Test.WriteLine("");
        }
	}
}
