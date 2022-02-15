using System;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.PKCS11
{
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм выработки подписи данных
	///////////////////////////////////////////////////////////////////////////
	public abstract class SignData : CAPI.SignData
	{
		// используемое устройство и сеанс
		private Applet applet; private Session session; 

		// конструктор
		public SignData(Applet applet)
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
		public override void Init(IPrivateKey privateKey, IRand rand)
        {
            // вызвать базовую функцию
            base.Init(privateKey, rand); 

	        // указать дополнительные атрибуты ключа
	        Attribute[] keyAttributes = new Attribute[] {
		        applet.Provider.CreateAttribute(API.CKA_SIGN, API.CK_TRUE)
	        }; 
	        // открыть сеанс
	        session = applet.OpenSession(API.CKS_RO_USER_FUNCTIONS);  
	        try { 
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
	        }
	        catch {
                // закрыть сеанс
                session.Dispose(); session = null; throw;
            }
        }
		// обработать данные
		public override void Update(byte[] data, int dataOff, int dataLen)
        {
	        // захэшировать данные
	        if (dataLen > 0) session.SignUpdate(data, dataOff, dataLen); 
        }
		// получить подпись данных
		public override byte[] Finish(IRand rand)
        {
	        // выделить память для подписи
	        byte[] signature = new byte[session.SignFinal(null, 0)]; 

	        // получить подпись
	        Array.Resize(ref signature, session.SignFinal(signature, 0));

            // закрыть сеанс
            session.Dispose(); session = null; base.Finish(rand); return signature;
        }
	}
}
