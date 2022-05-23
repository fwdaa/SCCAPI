using Aladdin.PKCS11; 

namespace Aladdin.CAPI.PKCS11
{
	///////////////////////////////////////////////////////////////////////////////
	// Алгоритм вычисления имитовставки PKCS11
	///////////////////////////////////////////////////////////////////////////////
	public abstract class Mac : CAPI.Mac
	{
		// используемое устройство и сеанс
		private Applet applet; private Session session; private int total; 

		// конструктор
		protected Mac(Applet applet)
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
		protected abstract Mechanism GetParameters(Session sesssion);  

        // общий размер данных
        protected int Total { get { return total; }}

		// атрибуты ключа
		protected virtual Attribute[] GetKeyAttributes(int keySize)
		{ 
			// атрибуты ключа
			return applet.Provider.SecretKeyAttributes(KeyFactory, keySize, true); 
		}
		// инициализировать алгоритм
		public override void Init(ISecretKey key)
        {
	        // указать дополнительные атрибуты ключа
	        Attribute[] keyAttributes = new Attribute[] {
		        applet.Provider.CreateAttribute(API.CKA_SIGN, API.CK_TRUE)
	        }; 
	        // получить атрибуты ключа
	        keyAttributes = Attribute.Join(keyAttributes, GetKeyAttributes(key.Length)); 

			// при необходимости закрыть старый сеанс
			if (session != null) { session.Dispose(); session = null; } 

	        // открыть сеанс
	        session = applet.OpenSession(API.CKS_RO_PUBLIC_SESSION); 
	        try {
		        // получить параметры алгоритма
		        Mechanism parameters = GetParameters(session); 

	            // преобразовать тип ключа
	            SessionObject sessionKey = applet.Provider.ToSessionObject(
                    session, key, keyAttributes
                ); 
		        // инициализировать алгоритм
		        session.SignInit(parameters, sessionKey.Handle); total = 0; 
	        }
			// при ошибке закрыть сеанс 
	        catch { session.Dispose(); session = null; throw; } 
        }
		// захэшировать данные
		public override void Update(byte[] data, int dataOff, int dataLen)
        {
	        // захэшировать данные
	        if (dataLen > 0) session.SignUpdate(data, dataOff, dataLen); 

            // увеличить общий размер
            total += dataLen; 
        }
		// завершить выработку имитовставки
		public override int Finish(byte[] buf, int bufOff)
        {
	        // завершить выработку имитовставки
	        int bufLen = session.SignFinal(buf, bufOff);

            // проверить указание буфера
	        if (buf == null) return bufLen;

            // закрыть сеанс
            session.Dispose(); session = null; return bufLen; 
        }
	}
}
