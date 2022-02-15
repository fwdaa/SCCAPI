package aladdin.capi.ansi.pkcs11.sign.dsa;
import aladdin.asn1.*;
import aladdin.asn1.ansi.x957.*;
import aladdin.capi.*; 
import aladdin.capi.pkcs11.*; 
import aladdin.capi.ansi.pkcs11.x957.*;
import java.security.*;
import java.io.*;

///////////////////////////////////////////////////////////////////////////
// Алгоритм проверки подписи DSA
///////////////////////////////////////////////////////////////////////////
public class VerifyData extends aladdin.capi.pkcs11.VerifyData
{
    // конструктор
	public VerifyData(Applet applet, long algID) 
    
        // сохранить переданные параметры
        { super(applet); this.algID = algID; } private final long algID;

	// параметры алгоритма
    @Override 
    protected Mechanism getParameters(Session sesssion, IParameters parameters)
	{
		// параметры алгоритма
		return new Mechanism(algID); 
	}
	// инициализировать алгоритм
    @Override
	public void init(IPublicKey publicKey, byte[] signature) 
        throws SignatureException, IOException
    {
        // преобразовать параметры алгоритма
        aladdin.capi.ansi.x957.IParameters parameters = 
            (aladdin.capi.ansi.x957.IParameters)publicKey.parameters(); 
        
        // раскодировать значение подписи
        DssSigValue encoded = new DssSigValue(Encodable.decode(signature)); 
        
        // вызвать базовую функцию
        super.init(publicKey, Encoding.encodeSignature(parameters, encoded)); 
    }
}
