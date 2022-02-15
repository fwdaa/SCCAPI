using System;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.PKCS11
{
	///////////////////////////////////////////////////////////////////////////////
	// Алгоритм обмена ключа PKCS11
	///////////////////////////////////////////////////////////////////////////////
	public abstract class TransportKeyUnwrap : CAPI.TransportKeyUnwrap
	{
		// используемое устройство
		private Applet applet;

		// конструктор
		protected TransportKeyUnwrap(Applet applet)
		 
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
		protected abstract Mechanism GetParameters(
			Session sesssion, IParameters parameters, TransportKeyData data
        ); 
		// действия стороны-получателя
		public override ISecretKey Unwrap(IPrivateKey privateKey, 
            TransportKeyData transportData, SecretKeyFactory keyFactory)
        {
	        // указать дополнительные атрибуты ключа
	        Attribute[] keyAttributes = new Attribute[] {
		        applet.Provider.CreateAttribute(API.CKA_UNWRAP, API.CK_TRUE)
	        }; 
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
	        // открыть сеанс /* TODO: */
	        using (Session session = applet.OpenSession(API.CKS_RW_USER_FUNCTIONS)) 
            {
	            // получить параметры алгоритма
	            Mechanism parameters = GetParameters(session, privateKey.Parameters, transportData); 
                
                // получить информацию алгоритма
                MechanismInfo info = applet.GetAlgorithmInfo(parameters.AlgID); 

	            // преобразовать тип ключа
	            SessionObject sessionKey = applet.Provider.ToSessionObject(
		            session, privateKey, info, keyAttributes
	            );
	            // расшифровать ключ
	            UInt64 hCEK = session.UnwrapKey(parameters, 
                    sessionKey.Handle, transportData.EncryptedKey, attributes
	            );
	            // создать объект сеансового ключа
	            SessionObject sessionCEK = new SessionObject(session, hCEK);

	            // вернуть расшифрованный ключ
	            return applet.Provider.ConvertSecretKey(sessionCEK, keyFactory);
            }
        }
	}
}
