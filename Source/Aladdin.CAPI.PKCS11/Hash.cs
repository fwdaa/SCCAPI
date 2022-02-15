using Aladdin.PKCS11; 

namespace Aladdin.CAPI.PKCS11
{
	///////////////////////////////////////////////////////////////////////////////
	// Алгоритм хэширования PKCS11
	///////////////////////////////////////////////////////////////////////////////
	public abstract class Hash : CAPI.Hash
	{
		// физическое устройство и используемый сеанс
		private Applet applet; private Session session; private int total; 

		// конструктор
		protected Hash(Applet applet)
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

		// инициализировать алгоритм
		public override void Init()
        {
	        // открыть новый сеанс
	        session = applet.OpenSession(API.CKS_RO_PUBLIC_SESSION); 
	        try { 
		        // получить параметры алгоритма
		        Mechanism parameters = GetParameters(session);

		        // инициализировать алгоритм
		        session.DigestInit(parameters); total = 0; 
	        }
	        catch { 
                // закрыть сеанс
                session.Dispose(); session = null; throw; 
            }
        }
		// захэшировать данные
		public override void Update(byte[] data, int dataOff, int dataLen)
        {
	        // захэшировать данные
	        if (dataLen > 0) session.DigestUpdate(data, dataOff, dataLen); 

            // увеличить общий размер
            total += dataLen; 
        }
		// завершить хэширование данных
		public override int Finish(byte[] buf, int bufOff)
        {
	        // завершить хэширование данных
	        int bufLen = session.DigestFinal(buf, bufOff);

	        // проверить указание буфера
	        if (buf == null) return bufLen; 
    
            // закрыть сеанс
            session.Dispose(); session = null; return bufLen; 
        }
	}
}
