using System; 

namespace Aladdin.CAPI
{
    ///////////////////////////////////////////////////////////////////////////
	// Алгоритм согласования ключа
    ///////////////////////////////////////////////////////////////////////////
	public interface IKeyAgreement : IAlgorithm
	{
	    // согласовать общий ключ на стороне отправителя
	    DeriveData DeriveKey(IPrivateKey privateKey, 
            IPublicKey publicKey, IRand rand, SecretKeyFactory keyFactory, int keySize
        );
 	    // согласовать общий ключ на стороне получателя
	    ISecretKey DeriveKey(IPrivateKey privateKey, 
            IPublicKey publicKey, byte[] random, SecretKeyFactory keyFactory, int keySize
        );
	}
}
