using System;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.PKCS11
{
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм шифрования ключа
	///////////////////////////////////////////////////////////////////////////
	public abstract class KeyWrap : CAPI.KeyWrap
	{
		// используемое устройство
		private Applet applet;

		// конструктор
		protected KeyWrap(Applet applet)
		 
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
		protected abstract Mechanism GetParameters(Session sesssion, IRand rand); 

		// атрибуты ключа
		protected virtual Attribute[] GetKeyAttributes(int keySize)
		{ 
			// атрибуты ключа
			return applet.Provider.SecretKeyAttributes(KeyFactory, keySize, true); 
		}
		// зашифровать ключ
		public override byte[] Wrap(IRand rand, ISecretKey key, ISecretKey CEK)
        {
	        // указать дополнительные атрибуты ключа
	        Attribute[] keyAttributes = new Attribute[] {
		        applet.Provider.CreateAttribute(API.CKA_WRAP, API.CK_TRUE)
	        }; 
	        // получить атрибуты ключа
	        keyAttributes = Attribute.Join(keyAttributes, GetKeyAttributes(key.Length));  

            // получить атрибуты защищаемого ключа
            Attribute[] attributes = applet.Provider.SecretKeyAttributes(
                CEK.KeyFactory, CEK.Length, true
            ); 
	        // открыть сеанс
	        using (Session session = applet.OpenSession(API.CKS_RO_PUBLIC_SESSION))
            {
	            // преобразовать тип ключа
	            SessionObject sessionKey = applet.Provider.ToSessionObject(
		            session, key, keyAttributes
	            );
	            // преобразовать тип ключа
	            SessionObject sessionCEK = applet.Provider.ToSessionObject(
		            session, CEK, attributes
	            );
	            // получить параметры алгоритма
	            Mechanism parameters = GetParameters(session, rand);
                
	            // зашифровать ключ
	            return session.WrapKey(parameters, sessionKey.Handle, sessionCEK.Handle);
            }
        }
		// расшифровать ключ
		public override ISecretKey Unwrap(ISecretKey key, 
            byte[] wrappedCEK, SecretKeyFactory keyFactory)
        {
	        // указать дополнительные атрибуты ключа
	        Attribute[] keyAttributes = new Attribute[] {
		        applet.Provider.CreateAttribute(API.CKA_UNWRAP, API.CK_TRUE)
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
                applet.Provider.SecretKeyAttributes(keyFactory, -1, false)
            ); 
	        // открыть сеанс
	        using (Session session = applet.OpenSession(API.CKS_RO_PUBLIC_SESSION)) 
            {
	            // преобразовать тип ключа
	            SessionObject sessionKey = applet.Provider.ToSessionObject(
		            session, key, keyAttributes
	            ); 
	            // получить параметры алгоритма
	            Mechanism parameters = GetParameters(session, null); 
                
	            // расшифровать ключ
	            UInt64 hCEK = session.UnwrapKey(
		            parameters, sessionKey.Handle, wrappedCEK, attributes
	            );
	            // создать объект сеансового ключа
	            SessionObject sessionCEK = new SessionObject(session, hCEK); 
		
	            // вернуть расшифрованный ключ
	            return applet.Provider.ConvertSecretKey(sessionCEK, keyFactory); 
            }
        }
	}
}
