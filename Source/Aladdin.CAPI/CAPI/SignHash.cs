using System; 
using System.Diagnostics.CodeAnalysis; 

namespace Aladdin.CAPI
{
    ///////////////////////////////////////////////////////////////////////////
	// Выработка подписи хэш-значения
    ///////////////////////////////////////////////////////////////////////////
    [SuppressMessage("Microsoft.Design", "CA1063:ImplementIDisposableCorrectly")]
	public abstract class SignHash : RefObject, IAlgorithm
	{
		// алгоритм подписи хэш-значения
		public abstract byte[] Sign(IPrivateKey key, 
            IRand rand, ASN1.ISO.AlgorithmIdentifier hashAlgorithm, byte[] hash
        );
        ////////////////////////////////////////////////////////////////////////////
        // Тест известного ответа
        ////////////////////////////////////////////////////////////////////////////
        protected static void KnownTest(SecurityObject scope, SignHash signHash, 
            IPublicKey publicKey, IPrivateKey privateKey, byte[][] random, 
            ASN1.ISO.AlgorithmIdentifier hashParameters, byte[] hash, byte[] check)
        {
            // импортировать пару в контейнер
            using (KeyPair keyPair = new KeyPair(scope, null, publicKey, privateKey, 
                null, KeyUsage.DigitalSignature, KeyFlags.None))
            {
                // указать генератор случайных данных
                using (Test.Rand rand = new Test.Rand(random))
                {
                    // подписать хэш-значение
                    byte[] signature = signHash.Sign(keyPair.PrivateKey, rand, hashParameters, hash); 

                    // проверить совпадение результатов
                    if (!Arrays.Equals(signature, check)) throw new ArgumentException();
                }
            }
        }
	}; 
}
