package aladdin.capi.pkcs11;
import aladdin.*; 
import aladdin.capi.*; 
import aladdin.pkcs11.*;
import java.security.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Алгоритм шифрования ключа
///////////////////////////////////////////////////////////////////////////
public abstract class KeyWrap extends aladdin.capi.KeyWrap
{
    // физическое устройство
    private final Applet applet;
    
	// конструктор
	protected KeyWrap(Applet applet)
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
	protected abstract Mechanism getParameters(Session sesssion, IRand rand); 

    // атрибуты ключа
    protected Attribute[] getKeyAttributes(int keySize)
    {
        // атрибуты ключа
        return applet.provider().secretKeyAttributes(keyFactory(), keySize, true); 
    }
	// зашифровать ключ
    @Override
	public byte[] wrap(IRand rand, ISecretKey key, ISecretKey CEK) 
        throws IOException, InvalidKeyException
    {
        // указать дополнительный атрибут ключа
        Attribute[] keyAttributes = new Attribute[] {
            new Attribute(API.CKA_WRAP, API.CK_TRUE)
        }; 
        // получить атрибуты ключа
        keyAttributes = Attribute.join(keyAttributes, getKeyAttributes(key.length()));  
        
        // указать атрибуты ключа
        Attribute[] attributes = applet.provider().secretKeyAttributes(
            CEK.keyFactory(), CEK.length(), true
        ); 
        // открыть сеанс
        try (Session session = applet.openSession(API.CKS_RO_PUBLIC_SESSION))
        {
            // получить параметры алгоритма
            Mechanism parameters = getParameters(session, rand); 
            
            // преобразовать тип ключа
            SessionObject sessionKey = applet.provider().toSessionObject(
                session, key, keyAttributes
            );
            // преобразовать тип ключа
            SessionObject sessionCEK = applet.provider().toSessionObject(
                session, CEK, attributes
            );
            // зашифровать ключ
            return session.wrapKey(
                parameters, sessionKey.handle(), sessionCEK.handle()
            );
        }
    }
	// расшифровать ключ
    @Override
	public ISecretKey unwrap(ISecretKey key, 
        byte[] wrappedCEK, SecretKeyFactory keyFactory) 
            throws IOException, InvalidKeyException
    {
        // указать дополнительный атрибут ключа
        Attribute[] keyAttributes = new Attribute[] {
            new Attribute(API.CKA_UNWRAP, API.CK_TRUE)
        }; 
        // получить атрибуты ключа
        keyAttributes = Attribute.join(keyAttributes, getKeyAttributes(key.length()));  
        
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
        // открыть сеанс
        try (Session session = applet.openSession(API.CKS_RO_PUBLIC_SESSION))
        {
            // получить параметры алгоритма
            Mechanism parameters = getParameters(session, null); 
            
            // преобразовать тип ключа
            SessionObject sessionKey = applet.provider().toSessionObject(
                session, key, keyAttributes
            ); 
            // расшифровать ключ
            long hCEK = session.unwrapKey(
                parameters, sessionKey.handle(), wrappedCEK, attributes
            );
            // создать объект сеансового ключа
            SessionObject sessionCEK = new SessionObject(session, hCEK); 

            // вернуть расшифрованный ключ
            return applet.provider().convertSecretKey(sessionCEK, keyFactory); 
        }
    }
};
