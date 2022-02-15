using Aladdin.PKCS11; 

namespace Aladdin.CAPI.PKCS11
{
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм проверки подписи хэш-значения
	///////////////////////////////////////////////////////////////////////////
	public abstract class VerifyHash : CAPI.VerifyHash
	{
		// используемое устройство
		private Applet applet;

		// конструктор
		protected VerifyHash(Applet applet)
		{  
			// сохранить переданные параметры
			this.applet = RefObject.AddRef(applet); 
		} 
        // деструктор
        protected override void OnDispose() 
        {
            // освободить выделенные ресурсы
            RefObject.Release(applet); base.OnDispose(); 
        }
		// используемое устройство
		protected Applet Applet { get { return applet; }} 

		// параметры алгоритма
		protected abstract Mechanism GetParameters(Session sesssion, IParameters parameters); 

		// алгоритм проверки подписи хэш-значения
		public override void Verify(IPublicKey publicKey, 
			ASN1.ISO.AlgorithmIdentifier hashAlgorithm, byte[] hash, byte[] signature)
        {
	        // указать дополнительные атрибуты ключа
	        Attribute[] keyAttributes = new Attribute[] {
		        applet.Provider.CreateAttribute(API.CKA_VERIFY, API.CK_TRUE)
	        }; 
	        // открыть сеанс
	        using (Session session = applet.OpenSession(API.CKS_RO_PUBLIC_SESSION))
            {
	            // получить параметры алгоритма
	            Mechanism parameters = GetParameters(session, publicKey.Parameters); 
                 
                // получить информацию алгоритма
                MechanismInfo info = applet.GetAlgorithmInfo(parameters.AlgID); 

	            // преобразовать тип ключа
	            SessionObject sessionKey = applet.Provider.ToSessionObject(
                    session, publicKey, info, keyAttributes
                ); 
	            // инициализировать алгоритм
	            session.VerifyInit(parameters, sessionKey.Handle);
		
	            // проверить подпись
	            session.Verify(hash, 0, hash.Length, signature); 
            }
        }
	}
}
