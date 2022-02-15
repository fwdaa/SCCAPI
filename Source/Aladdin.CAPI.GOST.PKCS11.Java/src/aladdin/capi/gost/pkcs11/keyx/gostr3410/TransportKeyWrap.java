package aladdin.capi.gost.pkcs11.keyx.gostr3410;
import aladdin.asn1.*; 
import aladdin.asn1.iso.*;
import aladdin.asn1.iso.pkix.*; 
import aladdin.pkcs11.*;
import aladdin.pkcs11.jni.*; 
import aladdin.capi.*; 
import aladdin.capi.pkcs11.*; 
import java.security.*;
import java.io.*;

///////////////////////////////////////////////////////////////////////////
// Алгоритм обмена ГОСТ Р 34.10-2001
///////////////////////////////////////////////////////////////////////////
public class TransportKeyWrap extends aladdin.capi.pkcs11.TransportKeyWrap
{
	// размер случайных данных
	private final int sizeUKM; 
	
	// конструктор
	public TransportKeyWrap(Applet applet, int sizeUKM)
    {
		// сохранить переданные параметры
		super(applet); this.sizeUKM = sizeUKM; 
	}
	// получить параметры
    @Override
	protected Mechanism getParameters(Session session, 
		IParameters parameters, IRand rand) throws IOException
    {
        // преобразовать тип параметров
        aladdin.capi.gost.gostr3410.INamedParameters gostParameters = 
            (aladdin.capi.gost.gostr3410.INamedParameters) parameters;

        // получить идентификатор таблицы подстановок для KEK
        byte[] wrapOID = new ObjectIdentifier(gostParameters.sboxOID()).encoded();
        
        // сгенерировать случайные данные
        byte[] ukm = new byte[sizeUKM]; rand.generate(ukm, 0, ukm.length);
        
        // вернуть параметры алгоритма
        return new Mechanism(API.CKM_GOSTR3410_KEY_WRAP, 
            new CK_GOSTR3410_KEY_WRAP_PARAMS(wrapOID, ukm, 0)
        ); 
    }
	// действия стороны-отправителя
    @Override
	public TransportKeyData wrap(AlgorithmIdentifier algorithmParameters, 
        IPublicKey publicKey, IRand rand, ISecretKey CEK) 
        throws IOException, InvalidKeyException
    {
        // закодировать открытый ключ
        SubjectPublicKeyInfo publicKeyInfo = publicKey.encoded(); 
        
        // вызвать базовую функцию
        return super.wrap(publicKeyInfo.algorithm(), publicKey, rand, CEK); 
    }
}; 
