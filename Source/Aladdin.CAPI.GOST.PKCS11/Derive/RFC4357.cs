using System;
using Aladdin.PKCS11;

namespace Aladdin.CAPI.GOST.PKCS11.Derive
{
    ///////////////////////////////////////////////////////////////////////////////
    // Алгоритм смены ключа RFC4357
    ///////////////////////////////////////////////////////////////////////////////
    public class RFC4357 : CAPI.PKCS11.KeyDerive
    {
        // закодированный идентификатор таблицы подстановок
        private byte[] encodedOID; 
    
	    // конструктор
	    public RFC4357(CAPI.PKCS11.Applet applet, string sboxOID) : base(applet) 
	    { 	 
		    // закодировать параметры алгоритма
		    encodedOID = new ASN1.ObjectIdentifier(sboxOID).Encoded;
        } 
	    // параметры алгоритма
	    protected override Mechanism GetParameters(CAPI.PKCS11.Session sesssion, byte[] random)
        {
            // параметры алгоритма
            return new Mechanism(API.CKM_KDF_4357, random); 
        }
		// атрибуты ключа
		protected override CAPI.PKCS11.Attribute[] GetKeyAttributes(int keySize)
		{ 
			// атрибуты ключа
			return new CAPI.PKCS11.Attribute[] { 

				// указать требуемые атрибуты
				Applet.Provider.CreateAttribute(API.CKA_KEY_TYPE, API.CKK_GOST28147),  

				// указать требуемые атрибуты
				Applet.Provider.CreateAttribute(API.CKA_GOST28147_PARAMS, encodedOID)
			}; 
		}
    }
}
