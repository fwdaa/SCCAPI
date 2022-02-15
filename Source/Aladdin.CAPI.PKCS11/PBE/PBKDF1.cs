using System;
using System.Security;
using System.Security.Permissions;
using System.Runtime.InteropServices;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.PKCS11.PBE
{
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм наследования ключа PBKDF1
    ///////////////////////////////////////////////////////////////////////////
    public class PBKDF1 : CAPI.KeyDerive
    {
        // алгоритм шифрования по паролю, salt-значение и число итераций
        private PBES1 pbes; private byte[] salt; private int iterations;
    
	    // конструктор
	    internal PBKDF1(PBES1 pbes, byte[] salt, int iterations)
        { 
		    // сохранить переданные параметры
		    this.pbes = pbes; this.salt = salt; this.iterations = iterations;
        }
	    // наследовать ключ
        [SecuritySafeCritical]
        [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
	    public override ISecretKey DeriveKey(ISecretKey password, 
            byte[] iv, SecretKeyFactory keyFactory, int deriveSize) 
        {
            // проверить наличие значения ключа
            if (password.Value == null) throw new Aladdin.PKCS11.Exception(API.CKR_KEY_UNEXTRACTABLE); 
        
            // проверить размер синхропосылки
            if (iv.Length != 8) throw new ArgumentException(); 
        
            // указать дополнительные атрибуты ключа
            Attribute[] keyAttributes = new Attribute[] {
                pbes.Applet.Provider.CreateAttribute(API.CKA_CLASS      , API.CKO_SECRET_KEY    ), 
                pbes.Applet.Provider.CreateAttribute(API.CKA_KEY_TYPE   , API.CKK_GENERIC_SECRET), 
                pbes.Applet.Provider.CreateAttribute(API.CKA_EXTRACTABLE, API.CK_TRUE           ), 
                pbes.Applet.Provider.CreateAttribute(API.CKA_SENSITIVE  , API.CK_FALSE          ), 
                pbes.Applet.Provider.CreateAttribute(API.CKA_TOKEN      , API.CK_FALSE          ) 
            };
            // указать дополнительные атрибуты ключа
            keyAttributes = Attribute.Join(keyAttributes, pbes.GetKeyAttributes());  
        
            // открыть сеанс
            using (Session session = pbes.Applet.OpenSession(API.CKS_RO_PUBLIC_SESSION))
            {
                // указать параметры алгоритма
                Parameters.CK_PBE_PARAMS pbeParams = new Parameters.CK_PBE_PARAMS(
                    Marshal.AllocHGlobal(iv.Length), password.Value, salt, iterations); 
                try { 
                   // указать идентификатор алгоритма генерации
                    Mechanism parameters = new Mechanism(pbes.AlgID, pbeParams); 
                    
                    // сгенерировать ключ и синхропосылку
                    SessionObject sessionKey = session.GenerateKey(parameters, keyAttributes); 
                
                    // скопировать значение синхропосылки
                    Marshal.Copy(pbeParams.IV, iv, 0, iv.Length); 

	                // вернуть унаследованный ключ
	                return pbes.Applet.Provider.ConvertSecretKey(sessionKey, keyFactory); 
                }
                // освободить выделенные ресурсы
                finally { Marshal.FreeHGlobal(pbeParams.IV); }
            }
        }
    }
}
