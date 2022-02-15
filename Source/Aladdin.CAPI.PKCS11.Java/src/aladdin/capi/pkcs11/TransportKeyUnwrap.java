package aladdin.capi.pkcs11;
import aladdin.*; 
import aladdin.capi.*; 
import aladdin.pkcs11.*;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм обмена ключа PKCS11
///////////////////////////////////////////////////////////////////////////////
public abstract class TransportKeyUnwrap extends aladdin.capi.TransportKeyUnwrap
{
    // физическое устройство
    private final Applet applet;
    
	// конструктор
	protected TransportKeyUnwrap(Applet applet) 
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

	// действия стороны-получателя
    @Override
	public ISecretKey unwrap(IPrivateKey privateKey, 
        TransportKeyData transportData, SecretKeyFactory keyFactory) throws IOException
    {
        // указать дополнительные атрибуты ключа
        Attribute[] keyAttributes = new Attribute[] {
            new Attribute(API.CKA_UNWRAP, API.CK_TRUE)
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
            applet.provider().secretKeyAttributes(keyFactory, -1, false)
        ); 
        // открыть сеанс /* TODO: */
        try (Session session = applet.openSession(API.CKS_RW_USER_FUNCTIONS))
        {
            // получить параметры алгоритма
            Mechanism parameters = getParameters(
                session, privateKey.parameters(), transportData
            ); 
            // получить информацию об алгоритме
            MechanismInfo info = applet.getAlgorithmInfo(parameters.id()); 
            
            // преобразовать тип ключа
            SessionObject sessionKey = applet.provider().toSessionObject(
                session, privateKey, info, keyAttributes
            );
            // расшифровать ключ
            long hCEK = session.unwrapKey(parameters, 
                sessionKey.handle(), transportData.encryptedKey, attributes
            );
            // создать объект сеансового ключа
            SessionObject sessionCEK = new SessionObject(session, hCEK);

            // вернуть расшифрованный ключ
            return applet.provider().convertSecretKey(sessionCEK, keyFactory);
        }
    }
	// параметры алгоритма
	protected abstract Mechanism getParameters(Session sesssion, 
        IParameters parameters, TransportKeyData data) throws IOException; 
};
