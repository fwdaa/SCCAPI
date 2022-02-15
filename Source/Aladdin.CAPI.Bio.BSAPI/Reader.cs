using System; 

namespace Aladdin.CAPI.Bio.BSAPI
{
	///////////////////////////////////////////////////////////////////////////
	// Считыватель отпечатков пальца
	///////////////////////////////////////////////////////////////////////////
    public class Reader : Bio.Reader
    {
        // используемый провайдер и имя считывателя
        private Provider provider; private string readerName; 

        // конструктор
        public Reader(Provider provider, string readerName)
        {
            // сохранить переданные параметры
            this.provider = RefObject.AddRef(provider); this.readerName = readerName; 
        }
        // деструктор
        protected override void OnDispose()
        {
            // освободить выделенные ресурсы
            RefObject.Release(provider); base.OnDispose();
        }
		// провайдер
	    public Provider Provider { get { return provider; }} 
        
        // имя считывателя
        public override string Name { get { return readerName; }} 
        
        // запустить процесс захвата отпечатка
        public override Remoting.RemoteClientControl BeginCapture(
            ImageTarget target, Predicate<Image> check, 
            TimeSpan timeout, Remoting.IBackgroundHandler handler)
        {
            // создать сеанс
            using (ReaderSession session = new ReaderSession(provider, readerName))
            {
                // запустить процесс захвата отпечатка
                return session.BeginCapture(target, check, timeout, handler); 
            }
        }
    }
}
