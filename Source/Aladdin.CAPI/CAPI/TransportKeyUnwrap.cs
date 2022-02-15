using System; 
using System.Diagnostics.CodeAnalysis; 

namespace Aladdin.CAPI
{
    ///////////////////////////////////////////////////////////////////////////
	// Формирование общего ключа на стороне-получателе
    ///////////////////////////////////////////////////////////////////////////
    [SuppressMessage("Microsoft.Design", "CA1063:ImplementIDisposableCorrectly")]
	public abstract class TransportKeyUnwrap : RefObject, IAlgorithm
	{
		// действия стороны-получателя
		public abstract ISecretKey Unwrap(IPrivateKey privateKey, 
            TransportKeyData transportData, SecretKeyFactory keyFactory
        );
        ////////////////////////////////////////////////////////////////////////////
        // Тест известного ответа
        ////////////////////////////////////////////////////////////////////////////
        protected static void KnownTest(SecurityObject scope, 
            TransportKeyUnwrap transportKeyUnwrap, IPublicKey publicKey, 
            IPrivateKey privateKey, byte[] CEK, TransportKeyData check) 
        {
            // указать фабрику кодирования ключей
            SecretKeyFactory keyFactory = SecretKeyFactory.Generic; 

            // импортировать пару в контейнер
            using (KeyPair keyPair = new KeyPair(scope, null, publicKey, privateKey, 
                null, KeyUsage.KeyAgreement, KeyFlags.None))
            {
                // расшифровать данные
                using (ISecretKey decrypted = transportKeyUnwrap.Unwrap(keyPair.PrivateKey, check, keyFactory))
                {
                    // проверить совпадение результата
                    if (!Arrays.Equals(decrypted.Value, CEK)) throw new ArgumentException();
                }
            }
        }
	}
}
