package aladdin.capi.pkcs11;
import aladdin.*; 
import aladdin.capi.*; 
import aladdin.pkcs11.*;
import java.io.*;

///////////////////////////////////////////////////////////////////////////////
// Алгоритм наследования ключа PKCS11
///////////////////////////////////////////////////////////////////////////////
public abstract class KeyAgreement extends aladdin.capi.KeyAgreement
{
    // физическое устройство
    private final Applet applet; 
    
	// конструктор
	protected KeyAgreement(Applet applet) 
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
	protected abstract Mechanism getParameters(Session sesssion, 
		IPublicKey publicKey, byte[] random, int keySize
    ); 
    // согласовать общий ключ
    @Override
	public ISecretKey deriveKey(IPrivateKey privateKey, 
		IPublicKey publicKey, byte[] random, 
        SecretKeyFactory keyFactory, int keySize) throws IOException
    {
        // при наличии эфемерного ключа
        if (privateKey.scope() == null && !applet.provider().canImportSessionPair(applet))
        {
            // создать программый алгоритм
            try (aladdin.capi.KeyAgreement algorithm = createSoftwareAlgorithm(publicKey.parameters()))
            {
                // проверить наличие алгоритма
                if (algorithm == null) throw new UnsupportedOperationException(); 
                
                // выполниить прграммную реализацию
                return algorithm.deriveKey(privateKey, publicKey, random, keyFactory, keySize); 
            }
        }
        // указать дополнительные атрибуты ключа
        Attribute[] keyAttributes = new Attribute[] {
            new Attribute(API.CKA_DERIVE, API.CK_TRUE)
        }; 
        // указать дополнительные атрибуты ключа
        Attribute[] attributes = new Attribute[] {
            new Attribute(API.CKA_CLASS      , API.CKO_SECRET_KEY    ), 
            new Attribute(API.CKA_KEY_TYPE   , API.CKK_GENERIC_SECRET), 
            new Attribute(API.CKA_EXTRACTABLE, API.CK_TRUE           ), 
            new Attribute(API.CKA_SENSITIVE  , API.CK_FALSE          ), 
            new Attribute(API.CKA_TOKEN      , API.CK_FALSE          ) 
        }; 
        // вычислить атрибуты ключа
        attributes = Attribute.join(attributes, 
            applet.provider().secretKeyAttributes(keyFactory, keySize, false)
        ); 
        // открыть сеанс /* TODO: */ 
        try (Session session = applet.openSession(API.CKS_RW_USER_FUNCTIONS))
        {
            // получить параметры алгоритма
            Mechanism parameters = getParameters(session, publicKey, random, keySize); 
            
            // получить информацию об алгоритме
            MechanismInfo info = applet.getAlgorithmInfo(parameters.id()); 
            
            // преобразовать тип ключа
            SessionObject sessionPrivateKey = applet.provider().toSessionObject(
                session, privateKey, info, keyAttributes
            );
            // наследовать ключ
            long hKey = session.deriveKey(parameters, sessionPrivateKey.handle(), attributes);
            
            // создать объект сеансового ключа
            SessionObject sessionKey = new SessionObject(session, hKey);

            // вернуть унаследованный ключ
            return applet.provider().convertSecretKey(sessionKey, keyFactory);
        }
    }
    // создать программный алгоритм
    protected aladdin.capi.KeyAgreement createSoftwareAlgorithm(
        IParameters parameters) throws IOException { return null; }
} 
