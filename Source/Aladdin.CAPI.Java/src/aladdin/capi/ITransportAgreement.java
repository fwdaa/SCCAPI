package aladdin.capi;
import java.security.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Алгоритм формирования общего ключа
///////////////////////////////////////////////////////////////////////////
public interface ITransportAgreement extends IAlgorithm
{
	// действия стороны-отправителя
	TransportAgreementData wrap(
        IPrivateKey senderPrivateKey, IPublicKey senderPublicKey, 
        IPublicKey[] recipientPublicKeys, IRand rand, ISecretKey key) 
        throws IOException, InvalidKeyException;
    
	// действия стороны-получателя
	ISecretKey unwrap(IPrivateKey recipientPrivateKey, 
        IPublicKey publicKey, byte[] random, 
        byte[] encryptedKey, SecretKeyFactory keyFactory) throws IOException;
}
