using System; 

namespace Aladdin.CAPI
{
    ///////////////////////////////////////////////////////////////////////////
	// Формирование общего ключа 
    ///////////////////////////////////////////////////////////////////////////
	public interface ITransportAgreement : IAlgorithm
	{
	    // действия стороны-отправителя
	    TransportAgreementData Wrap(IPrivateKey senderPrivateKey, 
            IPublicKey senderPublicKey, 
            IPublicKey[] recipientPublicKeys, IRand rand, ISecretKey key
        );
	    // действия стороны-получателя
	    ISecretKey Unwrap(IPrivateKey recipientPrivateKey, 
            IPublicKey publicKey, byte[] random, 
            byte[] encryptedKey, SecretKeyFactory keyFactory
        ); 
	}
}
