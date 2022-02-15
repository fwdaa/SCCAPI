package aladdin.capi.pkcs11.pbe;
import aladdin.*; 
import aladdin.capi.*;
import aladdin.capi.pkcs11.*; 
import aladdin.pkcs11.*;
import aladdin.pkcs11.jni.*;
import java.io.*;

///////////////////////////////////////////////////////////////////////////
// Алгоритм наследования ключа PBKDF2
///////////////////////////////////////////////////////////////////////////
public class PBKDF2 extends aladdin.capi.KeyDerive
{
    // тип структуры передачи параметров
    public static enum ParametersType { PARAMS2(0), PARAMS_LONG(1), PARAMS_PTR(2);
    
        // конструктор
        private ParametersType(int value) { intValue = value; } 

        // получить значение
        public int value() { return intValue; } private final int intValue;    
    }; 
    // физическое устройство и тип структуры передачи параметров
    private final Applet applet; private final ParametersType parametersType;
    // идентификатор алгоритма 
    private final long prf; private final Object prfData;
    // salt-значение и число итераций
    private final byte[] salt; private final int iterations; private final int keySize; 
    
    // конструктор
	public PBKDF2(Applet applet, ParametersType parametersType, 
        long prf, Object prfData, byte[] salt, int iterations, int keySize)
    { 
		// сохранить переданные параметры
		this.applet = RefObject.addRef(applet); this.parametersType = parametersType; 
        
		// сохранить переданные параметры
        this.prf = prf; this.prfData = prfData; this.salt = salt; 

		// сохранить переданные параметры
		this.iterations = iterations; this.keySize = keySize; 
    }
    // деструктор
    @Override protected void onClose() throws IOException   
    { 
        // освободить выделенные ресурсы
        RefObject.release(applet); super.onClose();
    } 
	// используемое устройство 
	public Applet applet() { return applet; }
    
	// наследовать ключ
    @Override public ISecretKey deriveKey(ISecretKey password, 
        byte[] random, SecretKeyFactory keyFactory, int deriveSize) throws IOException
    {
        // проверить размер ключа
        if (keySize >= 0 && keySize != deriveSize) 
        {
            // при ошибке выбросить исключение
            throw new UnsupportedOperationException(); 
        }
        // проверить корректность параметров
        if (deriveSize < 0) throw new IllegalArgumentException(); 
        
        // проверить наличие значения ключа
        if (password.value() == null) throw new aladdin.pkcs11.Exception(API.CKR_KEY_UNEXTRACTABLE); 
        
        // указать дополнительные атрибуты ключа
        Attribute[] keyAttributes = new Attribute[] {
            new Attribute(API.CKA_CLASS      , API.CKO_SECRET_KEY    ), 
            new Attribute(API.CKA_KEY_TYPE   , API.CKK_GENERIC_SECRET), 
            new Attribute(API.CKA_EXTRACTABLE, API.CK_TRUE           ), 
            new Attribute(API.CKA_TOKEN      , API.CK_FALSE          ), 
            new Attribute(API.CKA_VALUE_LEN  , deriveSize               ) 
        };
        // указать дополнительные атрибуты ключа
        keyAttributes = Attribute.join(keyAttributes, 
            applet.provider().secretKeyAttributes(keyFactory, deriveSize, false)
        );  
        // открыть сеанс
        try (Session session = applet.openSession(API.CKS_RO_PUBLIC_SESSION))
        {
            // в зависимости от типа передачи параметров
            if (parametersType.equals(ParametersType.PARAMS2))
            {
                // указать параметры алгоритма
                CK_PKCS5_PBKD2_PARAMS2 pbeParams2 = new CK_PKCS5_PBKD2_PARAMS2(
                    prf, prfData, password.value(), salt, iterations
                ); 
                // указать идентификатор алгоритма генерации
                Mechanism parameters = new Mechanism(API.CKM_PKCS5_PBKD2, pbeParams2); 
             
                // сгенерировать ключ и синхропосылку
                SessionObject sessionKey = session.generateKey(parameters, keyAttributes); 
                
                // вернуть унаследованный ключ
                return applet().provider().convertSecretKey(sessionKey, keyFactory); 
            }
            else {
                // указать признак наличия указателя
                boolean hasPointer = (parametersType.equals(ParametersType.PARAMS_PTR)); 
            
                // указать параметры алгоритма
                CK_PKCS5_PBKD2_PARAMS pbeParams = new CK_PKCS5_PBKD2_PARAMS(
                    hasPointer, prf, prfData, password.value(), salt, iterations
                ); 
                // указать идентификатор алгоритма генерации
                Mechanism parameters = new Mechanism(API.CKM_PKCS5_PBKD2, pbeParams);
                
                // сгенерировать ключ и синхропосылку
                SessionObject sessionKey = session.generateKey(parameters, keyAttributes); 
                
                // вернуть унаследованный ключ
                return applet().provider().convertSecretKey(sessionKey, keyFactory);
            }
        }
    }
}
