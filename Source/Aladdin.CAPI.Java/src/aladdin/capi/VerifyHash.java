package aladdin.capi;
import aladdin.*; 
import aladdin.asn1.iso.*; 
import java.security.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Проверка подписи хэш-значения
///////////////////////////////////////////////////////////////////////////
public abstract class VerifyHash extends RefObject implements IAlgorithm
{
	// алгоритм проверки подписи хэш-значения
	public abstract void verify(IPublicKey key, 
        AlgorithmIdentifier hashAgorithm, byte[] hash, byte[] signature) 
        throws IOException, SignatureException;

    ////////////////////////////////////////////////////////////////////////////
    // Тест известного ответа
    ////////////////////////////////////////////////////////////////////////////
    protected static void knownTest(VerifyHash verifyHash, IPublicKey publicKey, 
        AlgorithmIdentifier hashParameters, byte[] hash, byte[] signature) throws Exception
    {
        // проверить подпись хэш-значения
        verifyHash.verify(publicKey, hashParameters, hash, signature); 
    }
}
