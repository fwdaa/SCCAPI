package aladdin.capi.ansi.pkcs11.sign.dsa;
import aladdin.asn1.iso.*;
import aladdin.capi.*;
import aladdin.capi.pkcs11.*;
import aladdin.capi.ansi.pkcs11.x957.*;
import aladdin.pkcs11.*;
import java.io.*;

///////////////////////////////////////////////////////////////////////////
// Алгоритм подписи хэш-значения DSA
///////////////////////////////////////////////////////////////////////////
public class SignHash extends aladdin.capi.pkcs11.SignHash
{
    // конструктор
	public SignHash(Applet applet) { super(applet); } 

	// параметры алгоритма
    @Override 
    protected Mechanism getParameters(Session sesssion, IParameters parameters)
	{
		// параметры алгоритма
		return new Mechanism(API.CKM_DSA); 
	}
	// алгоритм подписи хэш-значения
    @Override
	public byte[] sign(IPrivateKey privateKey, IRand rand, 
        AlgorithmIdentifier hashAgorithm, byte[] hash) throws IOException
    {
        // преобразовать параметры алгоритма
        aladdin.capi.ansi.x957.IParameters parameters = 
            (aladdin.capi.ansi.x957.IParameters)privateKey.parameters(); 
        
        // подписать хэш-значение
        byte[] signature = super.sign(privateKey, rand, hashAgorithm, hash); 
        
        // закодировать подпись
        return Encoding.decodeSignature(parameters, signature).encoded(); 
    }
}
