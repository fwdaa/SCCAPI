using Aladdin.PKCS11; 

namespace Aladdin.CAPI.PKCS11
{
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм подписи хэш-значения
	///////////////////////////////////////////////////////////////////////////
	public abstract class SignHash : CAPI.SignHash
	{
		// используемое устройство
		private Applet applet;

		// конструктор
		protected SignHash(Applet applet)
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

		// алгоритм подписи хэш-значения
		public override byte[] Sign(IPrivateKey privateKey, IRand rand, 
			ASN1.ISO.AlgorithmIdentifier hashAlgorithm, byte[] hash)
        {
	        // указать дополнительные атрибуты ключа
	        Attribute[] keyAttributes = new Attribute[] {
		        applet.Provider.CreateAttribute(API.CKA_SIGN, API.CK_TRUE)
	        }; 
	        // открыть сеанс
	        using (Session session = applet.OpenSession(API.CKS_RO_USER_FUNCTIONS))
            {
	            // получить параметры алгоритма
	            Mechanism parameters = GetParameters(session, privateKey.Parameters); 
                 
                // получить информацию алгоритма
                MechanismInfo info = applet.GetAlgorithmInfo(parameters.AlgID); 

	            // преобразовать тип ключа
	            SessionObject sessionKey = applet.Provider.ToSessionObject(
                    session, privateKey, info, keyAttributes
                );
	            // инициализировать алгоритм
	            session.SignInit(parameters, sessionKey.Handle);

	            // подписать хэш-значение
	            return session.Sign(hash, 0, hash.Length);
            }
        }
	}
}
