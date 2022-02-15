using System;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.PKCS11
{
	///////////////////////////////////////////////////////////////////////////////
	// Алгоритм наследования ключа PKCS11
	///////////////////////////////////////////////////////////////////////////////
	public abstract class KeyDerive : CAPI.KeyDerive
	{
		// используемое устройство
		private Applet applet;

		// конструктор
		protected KeyDerive(Applet applet)
		 
			// сохранить переданные параметры
			{ this.applet = RefObject.AddRef(applet); } 

        // деструктор
        protected override void OnDispose() 
        {
            // освободить выделенные ресурсы
            RefObject.Release(applet); base.OnDispose(); 
        }
		// используемое устройство
		protected Applet Applet { get { return applet; }} 

		// параметры алгоритма
		protected abstract Mechanism GetParameters(Session sesssion, byte[] random); 

		// атрибуты ключа
		protected virtual Attribute[] GetKeyAttributes(int keySize) 
        { 
			// атрибуты ключа
			return applet.Provider.SecretKeyAttributes(KeyFactory, keySize, true); 
        }
		// наследовать ключ
		public override ISecretKey DeriveKey(ISecretKey key, 
            byte[] random, SecretKeyFactory keyFactory, int deriveSize)
        {
	        // указать дополнительные атрибуты ключа 
	        Attribute[] keyAttributes = new Attribute[] {
		        applet.Provider.CreateAttribute(API.CKA_DERIVE, API.CK_TRUE)
	        }; 
	        // получить атрибуты ключа
	        keyAttributes = Attribute.Join(keyAttributes, GetKeyAttributes(key.Length));  

	        // указать дополнительные атрибуты ключа
	        Attribute[] attributes = new Attribute[] {
		        applet.Provider.CreateAttribute(API.CKA_CLASS      , API.CKO_SECRET_KEY    ), 
		        applet.Provider.CreateAttribute(API.CKA_KEY_TYPE   , API.CKK_GENERIC_SECRET), 
		        applet.Provider.CreateAttribute(API.CKA_EXTRACTABLE, API.CK_TRUE           ), 
		        applet.Provider.CreateAttribute(API.CKA_SENSITIVE  , API.CK_FALSE          ), 
		        applet.Provider.CreateAttribute(API.CKA_TOKEN      , API.CK_FALSE          ) 
	        }; 
	        // вычислить атрибуты ключа
	        attributes = Attribute.Join(attributes, 
                applet.Provider.SecretKeyAttributes(keyFactory, deriveSize, false)
            ); 
	        // открыть сеанс
	        using (Session session = applet.OpenSession(API.CKS_RO_PUBLIC_SESSION)) 
            {
	            // получить параметры алгоритма
	            Mechanism parameters = GetParameters(session, random); 

	            // преобразовать тип ключа
	            SessionObject sessionBaseKey = applet.Provider.ToSessionObject(
		            session, key, keyAttributes
	            ); 
                // наследовать ключ
	            UInt64 hKey = session.DeriveKey(
		            parameters, sessionBaseKey.Handle, attributes
	            );
	            // создать объект сеансового ключа
	            SessionObject sessionKey = new SessionObject(session, hKey); 
		
                // вернуть унаследованный ключ
	            return applet.Provider.ConvertSecretKey(sessionKey, keyFactory); 
            }
        }
	}
}
