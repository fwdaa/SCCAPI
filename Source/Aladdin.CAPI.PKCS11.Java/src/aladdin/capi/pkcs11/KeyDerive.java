package aladdin.capi.pkcs11;
import aladdin.*; 
import aladdin.capi.*; 
import aladdin.pkcs11.*;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм наследования ключа PKCS11
///////////////////////////////////////////////////////////////////////////////
public abstract class KeyDerive extends aladdin.capi.KeyDerive
{
	// используемое устройство
	private final Applet applet;

	// конструктор
	protected KeyDerive(Applet applet)
		 
		// сохранить переданные параметры
		{ this.applet = RefObject.addRef(applet); } 

    // деструктор
    @Override protected void onClose() throws IOException   
    {
        // освободить выделенные ресурсы
        RefObject.release(applet); super.onClose(); 
    }
    // используемое устройство
	protected Applet applet() { return applet; } 

	// параметры алгоритма
	protected abstract Mechanism getParameters(Session sesssion, byte[] random); 

	// атрибуты ключа
	protected Attribute[] getKeyAttributes(int keySize) 
    { 
        // атрибуты ключа
        return applet.provider().secretKeyAttributes(keyFactory(), keySize, true); 
    }
	// наследовать ключ
	@Override public ISecretKey deriveKey(
        ISecretKey key, byte[] random, 
        SecretKeyFactory keyFactory, int deriveSize) throws IOException
    {
	    // указать дополнительные атрибуты ключа
	    Attribute[] keyAttributes = new Attribute[] {
	        new Attribute(API.CKA_DERIVE, API.CK_TRUE)
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
            applet.provider().secretKeyAttributes(keyFactory, deriveSize, false)
        ); 
	    // открыть сеанс
	    try (Session session = applet.openSession(API.CKS_RO_PUBLIC_SESSION)) 
        {
	        // получить параметры алгоритма
	        Mechanism parameters = getParameters(session, random); 
            
	        // преобразовать тип ключа
	        SessionObject sessionBaseKey = applet.provider().toSessionObject(
	            session, key, keyAttributes
	        ); 
	        // наследовать ключ
	        long hKey = session.deriveKey(
	            parameters, sessionBaseKey.handle(), attributes
	        );
	        // создать объект сеансового ключа
	        SessionObject sessionKey = new SessionObject(session, hKey); 
		
	        // вернуть унаследованный ключ
	        return applet.provider().convertSecretKey(sessionKey, keyFactory); 
        }
    }
}
