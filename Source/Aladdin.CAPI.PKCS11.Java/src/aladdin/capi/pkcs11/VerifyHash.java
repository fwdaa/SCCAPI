package aladdin.capi.pkcs11;
import aladdin.*; 
import aladdin.capi.*; 
import aladdin.asn1.iso.*; 
import aladdin.pkcs11.*;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Алгоритм проверки подписи хэш-значения
///////////////////////////////////////////////////////////////////////////
public abstract class VerifyHash extends aladdin.capi.VerifyHash
{
    // физическое устройство
    private final Applet applet;
    
	// конструктор
	protected VerifyHash(Applet applet) 
	{ 	
		// сохранить переданные параметры
		this.applet = RefObject.addRef(applet); 
    } 
	// деструктор
    @Override protected void onClose() throws IOException  
    { 
        // освободить выделенные ресурсы
        RefObject.release(applet); super.onClose();
    } 
	// используемое устройство 
	protected final Applet applet() { return applet; } 

	// параметры алгоритма
	protected abstract Mechanism getParameters(Session sesssion, IParameters parameters); 
    
	// алгоритм проверки подписи хэш-значения
    @Override
	public void verify(IPublicKey publicKey, AlgorithmIdentifier hashAgorithm, 
        byte[] hash, byte[] signature) throws IOException
    {
        // указать дополнительные атрибуты ключа
        Attribute[] keyAttributes = new Attribute[] {
            new Attribute(API.CKA_VERIFY, API.CK_TRUE)
        };  
        // открыть сеанс
        try (Session session = applet.openSession(API.CKS_RO_PUBLIC_SESSION)) 
        {
            // получить параметры алгоритма
            Mechanism parameters = getParameters(session, publicKey.parameters());
            
            // получить информацию об алгоритме
            MechanismInfo info = applet.getAlgorithmInfo(parameters.id()); 
            
            // преобразовать тип ключа
            SessionObject sessionKey = applet.provider().toSessionObject(
                session, publicKey, info, keyAttributes
            ); 
            // инициализировать алгоритм
            session.verifyInit(parameters, sessionKey.handle());

            // проверить подпись
            session.verify(hash, 0, hash.length, signature); 
        }
    }
}
