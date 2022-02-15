using System; 
using System.Diagnostics.CodeAnalysis; 

namespace Aladdin.CAPI
{
    ///////////////////////////////////////////////////////////////////////////
	// Формирование общего ключа на стороне-отправителе
    ///////////////////////////////////////////////////////////////////////////
    [SuppressMessage("Microsoft.Design", "CA1063:ImplementIDisposableCorrectly")]
	public abstract class TransportKeyWrap : RefObject, IAlgorithm
	{
		// действия стороны-отправителя
		public abstract TransportKeyData Wrap(
            ASN1.ISO.AlgorithmIdentifier algorithmParameters, 
            IPublicKey publicKey, IRand rand, ISecretKey key
        );
        ////////////////////////////////////////////////////////////////////////////
        // Тест известного ответа
        ////////////////////////////////////////////////////////////////////////////
        protected static void KnownTest(TransportKeyWrap transportKeyWrap, 
            ASN1.ISO.AlgorithmIdentifier algorithmParameters, IPublicKey publicKey, 
            byte[][] random, byte[] CEK, byte[] check)
        {
            // указать фабрику кодирования ключей
            SecretKeyFactory keyFactory = SecretKeyFactory.Generic; 

            // указать генератор случайных данных
            using (Test.Rand rand = new Test.Rand(random)) 
            {
                // указать используемый ключ
                using (ISecretKey key = keyFactory.Create(CEK))
                {
                    // зашифровать данные
                    TransportKeyData transportData = transportKeyWrap.Wrap(
                        algorithmParameters, publicKey, rand, key
                    ); 
                    // проверить совпадение результатов
                    if (!Arrays.Equals(transportData.EncryptedKey, check)) 
                    {
                        // при ошибке выбросить исключение
                        throw new ArgumentException();             
                    }
                }
            }
        }
	}
}
