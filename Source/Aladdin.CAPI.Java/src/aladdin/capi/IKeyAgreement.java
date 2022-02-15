package aladdin.capi;
import java.io.*;

///////////////////////////////////////////////////////////////////////////
// Алгоритм согласования общего ключа
///////////////////////////////////////////////////////////////////////////
public interface IKeyAgreement extends IAlgorithm
{
	// согласовать общий ключ на стороне отправителя
	DeriveData deriveKey(IPrivateKey privateKey, IPublicKey publicKey, 
        IRand rand, SecretKeyFactory keyFactory, int keySize) throws IOException;
    
 	// согласовать общий ключ на стороне получателя
	ISecretKey deriveKey(IPrivateKey privateKey, IPublicKey publicKey, 
        byte[] random, SecretKeyFactory keyFactory, int keySize) throws IOException;
}
