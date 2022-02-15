package aladdin.capi.ansi.pkcs11.sign.rsa.pkcs1;
import aladdin.asn1.*; 
import aladdin.asn1.iso.*; 
import aladdin.asn1.iso.pkcs.*;
import aladdin.capi.*; 
import aladdin.capi.pkcs11.*; 
import aladdin.pkcs11.*;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Алгоритм подписи хэш-значения RSA PKCS1
///////////////////////////////////////////////////////////////////////////
public class VerifyHash extends aladdin.capi.pkcs11.VerifyHash
{
    // конструктор
	public VerifyHash(Applet applet) { super(applet); } 

	// параметры алгоритма
    @Override 
    protected Mechanism getParameters(Session sesssion, IParameters parameters)
	{
		// параметры алгоритма
		return new Mechanism(API.CKM_RSA_PKCS); 
	}
    @Override public void verify(aladdin.capi.IPublicKey key, 
        AlgorithmIdentifier hashAlgorithm, byte[] hash, 
        byte[] signature) throws IOException
    {
        // закодировать хэш-значение 
        DigestInfo digestInfo = new DigestInfo(hashAlgorithm, new OctetString(hash)); 
        
        // вызвать базовую функцию
        super.verify(key, hashAlgorithm, digestInfo.encoded(), signature);
    }
}
