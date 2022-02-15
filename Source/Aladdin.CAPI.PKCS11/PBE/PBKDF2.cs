using System;
using System.Security;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.PKCS11.PBE
{
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм наследования ключа PBKDF2
    ///////////////////////////////////////////////////////////////////////////
    public class PBKDF2 : CAPI.KeyDerive
    {
        // тип структуры передачи параметров
        public enum ParametersType { Params2, ParamsLong, ParamsPtr }; 

        // физическое устройство и тип структуры передачи параметров
        private CAPI.PKCS11.Applet applet; private ParametersType parametersType; 
        // идентификатор алгоритма 
        private ulong prf; private byte[] prfData; 
        // salt-значение и число итераций
        private byte[] salt; private int iterations; private int keySize; 
    
	    // конструктор
	    public PBKDF2(CAPI.PKCS11.Applet applet, ParametersType parametersType, ulong prf, 
            byte[] prfData, byte[] salt, int iterations, int keySize)
        { 
		    // сохранить переданные параметры
		    this.applet = RefObject.AddRef(applet); this.parametersType = parametersType; 
            
		    // сохранить переданные параметры
            this.prf = prf; this.prfData = prfData; this.salt = salt; 

		    // сохранить переданные параметры
		    this.iterations = iterations; this.keySize = keySize; 
        }
        // деструктор
        protected override void OnDispose() 
        { 
            // освободить выделенные ресурсы
            RefObject.Release(applet); base.OnDispose();
        } 
	    // используемое устройство 
	    public CAPI.PKCS11.Applet Applet { get { return applet; }}
    
	    // наследовать ключ
	    public override ISecretKey DeriveKey(ISecretKey password, 
            byte[] random, SecretKeyFactory keyFactory, int deriveSize) 
        {
            // проверить размер ключа
            if (keySize >= 0 && keySize != deriveSize) 
            {
                // при ошибке выбросить исключение
                throw new NotSupportedException(); 
            }
            // проверить корректность параметров
            if (deriveSize < 0) throw new ArgumentException(); 

            // проверить наличие значения ключа
            if (password.Value == null) throw new Aladdin.PKCS11.Exception(API.CKR_KEY_UNEXTRACTABLE); 
        
            // указать дополнительные атрибуты ключа
            Attribute[] keyAttributes = new Attribute[] {
                applet.Provider.CreateAttribute(API.CKA_CLASS      , API.CKO_SECRET_KEY    ), 
                applet.Provider.CreateAttribute(API.CKA_KEY_TYPE   , API.CKK_GENERIC_SECRET), 
                applet.Provider.CreateAttribute(API.CKA_EXTRACTABLE, API.CK_TRUE           ),  
                applet.Provider.CreateAttribute(API.CKA_SENSITIVE  , API.CK_FALSE          ),  
                applet.Provider.CreateAttribute(API.CKA_TOKEN      , API.CK_FALSE          )
            };
            // указать дополнительные атрибуты ключа
            keyAttributes = Attribute.Join(keyAttributes, 
                applet.Provider.SecretKeyAttributes(keyFactory, deriveSize, false)
            );  
            // открыть сеанс
            using (Session session = applet.OpenSession(API.CKS_RO_PUBLIC_SESSION))
            {
                // в зависимости от типа передачи параметров
                if (parametersType == ParametersType.Params2)
                {
                    // указать параметры алгоритма
                    Parameters.CK_PKCS5_PBKD2_PARAMS2 pbeParams2 = new Parameters.CK_PKCS5_PBKD2_PARAMS2(
                        prf, prfData, password.Value, salt, iterations
                    ); 
                    // указать идентификатор алгоритма генерации
                    Mechanism parameters = new Mechanism(API.CKM_PKCS5_PBKD2, pbeParams2);
                  
                    // сгенерировать ключ
                    SessionObject sessionKey = session.GenerateKey(parameters, keyAttributes); 
                
                    // вернуть унаследованный ключ
                    return applet.Provider.ConvertSecretKey(sessionKey, keyFactory); 
                }
                else { 
                    // указать признак наличия указателя
                    bool hasPointer = (parametersType == ParametersType.ParamsPtr); 

                    // указать параметры алгоритма
                    Parameters.CK_PKCS5_PBKD2_PARAMS pbeParams = new Parameters.CK_PKCS5_PBKD2_PARAMS(
                        hasPointer, prf, prfData, password.Value, salt, iterations
                    ); 
                    // указать идентификатор алгоритма генерации
                    Mechanism parameters = new Mechanism(API.CKM_PKCS5_PBKD2, pbeParams);

                    // сгенерировать ключ 
                    SessionObject sessionKey = session.GenerateKey(parameters, keyAttributes); 
                
                    // вернуть унаследованный ключ
                    return applet.Provider.ConvertSecretKey(sessionKey, keyFactory); 
                }
            }
        }
    }
}
