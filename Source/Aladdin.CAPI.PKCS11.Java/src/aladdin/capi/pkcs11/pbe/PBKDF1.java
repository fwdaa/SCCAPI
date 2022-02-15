package aladdin.capi.pkcs11.pbe;
import aladdin.capi.*;
import aladdin.capi.pkcs11.*; 
import aladdin.pkcs11.*;
import aladdin.pkcs11.jni.*;
import java.io.*;

///////////////////////////////////////////////////////////////////////////
// Алгоритм наследования ключа PBKDF1
///////////////////////////////////////////////////////////////////////////
public class PBKDF1 extends aladdin.capi.KeyDerive
{
    // алгоритм шифрования по паролю, salt-значение и число итераций
    private final PBES1 pbes; private final byte[] salt; private final int iterations;
    
	// конструктор
	protected PBKDF1(PBES1 pbes, byte[] salt, int iterations)
    { 
		// сохранить переданные параметры
		this.pbes = pbes; this.salt = salt; this.iterations = iterations;
    }
	// наследовать ключ
	@Override public ISecretKey deriveKey(ISecretKey password, 
        byte[] iv, SecretKeyFactory keyFactory, int deriveSize) throws IOException
    {
        // проверить наличие значения ключа
        if (password.value() == null) throw new aladdin.pkcs11.Exception(API.CKR_KEY_UNEXTRACTABLE); 
        
        // проверить размер синхропосылки
        if (iv.length != 8) throw new IllegalArgumentException(); 
        
        // указать дополнительные атрибуты ключа
        Attribute[] keyAttributes = new Attribute[] {
            new Attribute(API.CKA_CLASS      , API.CKO_SECRET_KEY    ), 
            new Attribute(API.CKA_KEY_TYPE   , API.CKK_GENERIC_SECRET), 
            new Attribute(API.CKA_EXTRACTABLE, API.CK_TRUE           ), 
            new Attribute(API.CKA_TOKEN      , API.CK_FALSE          )
        };
        // указать дополнительные атрибуты ключа
        keyAttributes = Attribute.join(keyAttributes, pbes.getKeyAttributes());  
        
        // открыть сеанс
        try (Session session = pbes.applet().openSession(API.CKS_RO_PUBLIC_SESSION))
        {
            // указать параметры алгоритма
            CK_PBE_PARAMS pbeParams = new CK_PBE_PARAMS(iv, password.value(), salt, iterations); 
        
            // указать идентификатор алгоритма генерации
            Mechanism parameters = new Mechanism(pbes.algID(), pbeParams); 
            
            // сгенерировать ключ и синхропосылку
            SessionObject sessionKey = session.generateKey(parameters, keyAttributes); 
                
            // вернуть унаследованный ключ
            return pbes.applet().provider().convertSecretKey(sessionKey, keyFactory); 
        }
    }
}
