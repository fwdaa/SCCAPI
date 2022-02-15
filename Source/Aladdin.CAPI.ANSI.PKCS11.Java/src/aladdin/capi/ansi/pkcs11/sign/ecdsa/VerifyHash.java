package aladdin.capi.ansi.pkcs11.sign.ecdsa;
import aladdin.asn1.*;
import aladdin.asn1.iso.*;
import aladdin.asn1.ansi.x962.*;
import aladdin.capi.*; 
import aladdin.capi.pkcs11.*; 
import aladdin.capi.ansi.pkcs11.x962.*;
import aladdin.pkcs11.*;
import java.io.*;

///////////////////////////////////////////////////////////////////////////
// Алгоритм подписи хэш-значения DSA
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
		return new Mechanism(API.CKM_ECDSA); 
	}
	// алгоритм проверки подписи хэш-значения
    @Override
	public void verify(IPublicKey publicKey, AlgorithmIdentifier hashAgorithm, 
        byte[] hash, byte[] signature) throws IOException
    {
        // преобразовать параметры алгоритма
        aladdin.capi.ansi.x962.IParameters parameters = 
            (aladdin.capi.ansi.x962.IParameters)publicKey.parameters(); 
        
        // раскодировать значение подписи
        ECDSASigValue encoded = new ECDSASigValue(Encodable.decode(signature)); 
        
        // закодировать подпись
        signature = Encoding.encodeSignature(parameters, encoded); 
        
        // проверить подпись
        super.verify(publicKey, hashAgorithm, hash, signature); 
    }
}
