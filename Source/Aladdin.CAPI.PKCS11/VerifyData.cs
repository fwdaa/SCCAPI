using Aladdin.PKCS11; 

namespace Aladdin.CAPI.PKCS11
{
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм проверки подписи данных
	///////////////////////////////////////////////////////////////////////////
	public abstract class VerifyData : CAPI.VerifyData
	{
		// используемое устройство и сеанс
		private Applet applet; private Session session; 

		// конструктор
		public VerifyData(Applet applet)
		{
			// сохранить переданные параметры
			this.applet = RefObject.AddRef(applet); session = null;
		}
        // деструктор
        protected override void OnDispose() 
        {
            // освободить выделенные ресурсы
            if (session != null) session.Dispose(); 
            
            // освободить выделенные ресурсы
            RefObject.Release(applet); base.OnDispose(); 
        }
		// используемое устройство
		protected Applet Applet { get { return applet; }} 

		// параметры алгоритма
		protected abstract Mechanism GetParameters(Session sesssion, IParameters parameters); 

		// инициализировать алгоритм
		public override void Init(IPublicKey publicKey, byte[] signature)
        {
            // вызвать базовую функцию
            base.Init(publicKey, signature); 

	        // указать дополнительные атрибуты ключа
	        Attribute[] keyAttributes = new Attribute[] {
		        applet.Provider.CreateAttribute(API.CKA_VERIFY, API.CK_TRUE)
	        }; 
			// при необходимости закрыть старый сеанс
			if (session != null) { session.Dispose(); session = null; } 

	        // открыть сеанс
	        session = applet.OpenSession(API.CKS_RO_PUBLIC_SESSION); 
	        try { 
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
	        }
            // при ошибке закрыть сеанс
	        catch { session.Dispose(); session = null; throw; }
        }
		// обработать данные
		public override void Update(byte[] data, int dataOff, int dataLen)
        {
	        // захэшировать данные
	        if (dataLen > 0) session.VerifyUpdate(data, dataOff, dataLen); 
        }
		// проверить подпись данных
		public override void Finish()
        {
		    // проверить подпись
		    try { session.VerifyFinal(Signature); }
            
            // закрыть сеанс
            finally { session.Dispose(); session = null; } 
        }
	}
}
