using System;
using System.IO;
using System.Threading;
using System.ComponentModel;

namespace Aladdin.CAPI.Bio.BSAPI
{
    ///////////////////////////////////////////////////////////////////////
    // Управление захватом отпечатка пальца
    ///////////////////////////////////////////////////////////////////////
    public class CaptureClient : Remoting.RemoteClient
    {
	    // соединение с биометрическим устройством
        private ReaderSession session; 
        
        // параметры захвата отпечатка пальца
        private ImageTarget target; private ImageFormat format; 
        // параметры захвата отпечатка пальца
        private Predicate<Image> check; private TimeSpan timeout; 

        // конструктор
        public CaptureClient(ReaderSession session, ImageTarget target, 
            ImageFormat format, Predicate<Image> check, TimeSpan timeout)
        {
            // сохранить переданные параметры
            this.session = RefObject.AddRef(session); this.target = target; 

            // сохранить переданные параметры
            this.format = format; this.check = check; this.timeout = timeout; 
        }
        // деструктор
        protected override void OnDispose()
        {
            // освободить выделенные параметры
            RefObject.Release(session); base.OnDispose();
        }
        // создать объект управления захватом
        protected override Remoting.RemoteClientControl CreateRemoteControl(Remoting.IBackgroundTask task)
        {
            // создать объект управления захватом
            return new CaptureControl(task, session); 
        }
        // функция потока 
        public override void ThreadProc(Remoting.IBackgroundTask task, DoWorkEventArgs args)
        {
            // указать используемый идентификатор 
            Image image = null; int id = Thread.CurrentThread.ManagedThreadId; 
            
            // указать режим уведомлений
			NotificationMode mode = NotificationMode.LowLevelCallback; 
            do {
			    // захватить отпечаток пальца
			    ImageInfo info = session.GrabImage(
                    id, target, format, (int)timeout.TotalMilliseconds, mode, null, null
                ); 
			    // проверить наличие отпечатка пальца
			    if (info.Bitmap == null) throw new IOException(); 

                // выполнить преобразование типа
                image = session.Provider.CreateImage(info.Bitmap); 
            }
            // проверить выполнение условия
            while (!check(image)); args.Result = image; 
        }
    }
}
