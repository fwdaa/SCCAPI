using System;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.PKCS11
{
	///////////////////////////////////////////////////////////////////////////////
	// Алгоритм наследования ключа PKCS11
	///////////////////////////////////////////////////////////////////////////////
	public abstract class KeyAgreement : CAPI.KeyAgreement
	{
		// используемое устройство
		private Applet applet;

		// конструктор
		protected KeyAgreement(Applet applet)
		 
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
		protected abstract Mechanism GetParameters(Session sesssion, 
			IPublicKey publicKey, byte[] random, int keySize
        ); 
	    // согласовать общий ключ на стороне оправителя
        public override DeriveData DeriveKey(IPrivateKey privateKey, 
            IPublicKey publicKey, IRand rand, SecretKeyFactory keyFactory, int keySize)
        {
            // сгенерировать случайные данные
            byte[] random = Generate(privateKey.Parameters, rand);

            // согласовать общий ключ на стороне отправителя
            using (ISecretKey key = DeriveKey(privateKey, publicKey, random, keyFactory, keySize))
            {
                // вернуть согласованный ключ
                return new DeriveData(key, random); 
            }
        }
		// согласовать общий ключ на стороне получателя
		public override ISecretKey DeriveKey(IPrivateKey privateKey, 
			IPublicKey publicKey, byte[] random, SecretKeyFactory keyFactory, int keySize)
        {
            // при наличии эфемерного ключа
            if (privateKey.Scope == null && !applet.Provider.CanImportSessionPair(applet))
            {
                // создать программый алгоритм
                using (CAPI.KeyAgreement algorithm = CreateSoftwareAlgorithm(publicKey.Parameters))
                {
                    // проверить наличие алгоритма
                    if (algorithm == null) throw new NotSupportedException(); 

                    // выполниить прграммную реализацию
                    return algorithm.DeriveKey(privateKey, publicKey, random, keyFactory, keySize); 
                }
            }
	        // указать дополнительные атрибуты ключа 
	        Attribute[] keyAttributes = new Attribute[] {
		        applet.Provider.CreateAttribute(API.CKA_DERIVE, API.CK_TRUE)
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
                applet.Provider.SecretKeyAttributes(keyFactory, keySize, false)
            ); 
	        // открыть сеанс /* TODO: */ 
	        using (Session session = applet.OpenSession(API.CKS_RW_USER_FUNCTIONS))
            {
	            // получить параметры алгоритма
	            Mechanism parameters = GetParameters(session, publicKey, random, keySize); 
                
                // получить информацию алгоритма
                MechanismInfo info = applet.GetAlgorithmInfo(parameters.AlgID); 

	            // преобразовать тип ключа
	            SessionObject sessionBaseKey = applet.Provider.ToSessionObject(
		            session, privateKey, info, keyAttributes
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
        // создать программный алгоритм
        protected virtual CAPI.KeyAgreement CreateSoftwareAlgorithm(
            IParameters parameters) { return null; }
	} 
}
