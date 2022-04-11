using System; 
using System.Diagnostics.CodeAnalysis; 

namespace Aladdin.CAPI
{
    ///////////////////////////////////////////////////////////////////////////
	// Алгоритм зашифрования ключа
    ///////////////////////////////////////////////////////////////////////////
    [SuppressMessage("Microsoft.Design", "CA1063:ImplementIDisposableCorrectly")]
	public abstract class KeyWrap : RefObject, IAlgorithm
	{
        // тип ключа
        public virtual SecretKeyFactory KeyFactory  { get { return SecretKeyFactory.Generic; }}

		// зашифровать ключ
		public abstract byte[] Wrap(IRand rand, ISecretKey key, ISecretKey CEK);
		// расшифровать ключ
		public abstract ISecretKey Unwrap(ISecretKey key, byte[] wrappedCEK, SecretKeyFactory keyFactory);

        ////////////////////////////////////////////////////////////////////////////
        // Тест известного ответа
        ////////////////////////////////////////////////////////////////////////////
        public static void KnownTest(Test.Rand rand, 
            KeyWrap algorithm, byte[] KEK, byte[] CEK, byte[] result) 
        {
            // указать фабрику кодирования ключей
            SecretKeyFactory keyFactory = SecretKeyFactory.Generic; 

            // указать используемый ключ
            using (ISecretKey k1 = algorithm.KeyFactory.Create(KEK))
            {
                // вывести сообщение
                Test.Dump("KEK", k1.Value); 
                
                // указать используемый ключ
                using (ISecretKey k2 = keyFactory.Create(CEK))
                {
                    // вывести сообщение
                    Test.Dump("CEK", k2.Value); 

                    // выполнить шифрование ключа
                    byte[] wrapped = algorithm.Wrap(rand, k1, k2);

                    // вывести сообщение
                    Test.Dump("Required", result); Test.Dump("Wrapped", wrapped); 

                    // сравнить результат
                    if (!Arrays.Equals(wrapped, result)) throw new ArgumentException(); 

                    // расшифровать ключ
                    using (ISecretKey unwrapped = algorithm.Unwrap(k1, wrapped, keyFactory))
                    { 
                        // вывести сообщение
                        Test.Dump("Unwrapped", unwrapped.Value); 

                        // сравнить результат
                        if (!Arrays.Equals(unwrapped.Value, k2.Value)) throw new ArgumentException();
                
                        // вывести сообщение
                        Test.WriteLine("OK"); Test.WriteLine();
                    }
                }
            }
        }
	}
}
