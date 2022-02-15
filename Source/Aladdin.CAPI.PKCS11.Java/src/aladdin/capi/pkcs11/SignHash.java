package aladdin.capi.pkcs11;
import aladdin.*; 
import aladdin.capi.*; 
import aladdin.asn1.iso.*; 
import aladdin.pkcs11.*;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Алгоритм подписи хэш-значения
///////////////////////////////////////////////////////////////////////////
public abstract class SignHash extends aladdin.capi.SignHash
{
    // физическое устройство
    private final Applet applet;
    
	// конструктор
	protected SignHash(Applet applet) 
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
    
	// алгоритм подписи хэш-значения
    @Override
	public byte[] sign(IPrivateKey privateKey, IRand rand, 
        AlgorithmIdentifier hashAgorithm, byte[] hash) throws IOException
    {
        // указать дополнительные атрибуты ключа
        Attribute[] keyAttributes = new Attribute[] {
            new Attribute(API.CKA_SIGN,  API.CK_TRUE)
        }; 
        // открыть сеанс
        try (Session session = applet.openSession(API.CKS_RO_USER_FUNCTIONS))
        {
            // получить параметры алгоритма
            Mechanism parameters = getParameters(session, privateKey.parameters());
            
            // получить информацию об алгоритме
            MechanismInfo info = applet.getAlgorithmInfo(parameters.id()); 
            
            // преобразовать тип ключа
            SessionObject sessionKey = applet.provider().toSessionObject(
                session, privateKey, info, keyAttributes
            );
            // инициализировать алгоритм
            session.signInit(parameters, sessionKey.handle());

            // подписать хэш-значение
            return session.sign(hash, 0, hash.length);
        }
    }
};
