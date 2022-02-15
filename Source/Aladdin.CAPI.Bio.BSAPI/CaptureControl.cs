namespace Aladdin.CAPI.Bio.BSAPI
{
    ///////////////////////////////////////////////////////////////////////
    // Объект управления захватом отпечатка пальца
    ///////////////////////////////////////////////////////////////////////
    public sealed class CaptureControl : Remoting.RemoteClientControl
    {
	    // соединение с биометрическим устройством
        private ReaderSession session; 

	    // конструктор
	    public CaptureControl(Remoting.IBackgroundTask task, ReaderSession session) : base(task) 
        { 
            // запустить поток прослушивания
            this.session = RefObject.AddRef(session); 
        }
        // деструктор
        protected override void OnDispose()
        {
            // освободить выделенные параметры
            RefObject.Release(session); base.OnDispose();
        }
        // остановить процесс захвата
        public override void Cancel() 
        { 
            // получить идентификатор потока 
            base.Cancel(); int threadID = ThreadID; if (threadID != 0)
            { 
                // остановить процесс захвата
                session.CancelOperation(threadID);  
            } 
        } 
    }
}
