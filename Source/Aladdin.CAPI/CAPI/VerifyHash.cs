using System; 
using System.Diagnostics.CodeAnalysis; 

namespace Aladdin.CAPI
{
    ///////////////////////////////////////////////////////////////////////////
	// Проверка подписи хэш-значения
    ///////////////////////////////////////////////////////////////////////////
    [SuppressMessage("Microsoft.Design", "CA1063:ImplementIDisposableCorrectly")]
	public abstract class VerifyHash : RefObject, IAlgorithm
	{
		// алгоритм проверки подписи хэш-значения
		public abstract void Verify(IPublicKey key, 
            ASN1.ISO.AlgorithmIdentifier hashAlgorithm, byte[] hash, byte[] signature
        );
        ////////////////////////////////////////////////////////////////////////////
        // Тест известного ответа
        ////////////////////////////////////////////////////////////////////////////
        protected static void KnownTest(VerifyHash verifyHash, IPublicKey publicKey, 
            ASN1.ISO.AlgorithmIdentifier hashParameters, byte[] hash, byte[] signature) 
        {
            // проверить подпись хэш-значения
            verifyHash.Verify(publicKey, hashParameters, hash, signature); 
        }
	}
}
