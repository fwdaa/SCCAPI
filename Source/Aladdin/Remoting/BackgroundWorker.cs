using System;
using System.Threading;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;

namespace Aladdin.Remoting
{
    ///////////////////////////////////////////////////////////////////////////
    // Задание, выполняемое удаленно
    ///////////////////////////////////////////////////////////////////////////
    [SuppressMessage("Microsoft.Design", "CA1063:ImplementIDisposableCorrectly")]
    public sealed class BackgroundWorker : RefObject, IBackgroundTask
    {
        // объект управления заданием
        private readonly System.ComponentModel.BackgroundWorker worker; 

        // функция задания и идентификатор потока
        private readonly RemoteClient client; private int threadID; 
        // обработчик событий
        private readonly IBackgroundHandler handler; 

        // конструктор
        public BackgroundWorker(RemoteClient client, IBackgroundHandler handler)
        {
            // создать объект управления заданием
            worker = new System.ComponentModel.BackgroundWorker(); 

            // указать свойства задания
            worker.WorkerReportsProgress = true; worker.WorkerSupportsCancellation = true; 

            // сохранить функцию задания
            this.client = RefObject.AddRef(client); this.handler = handler; 

            // указать задание
            worker.DoWork += delegate(object sender, DoWorkEventArgs e)
            {
                // сохранить идентификатор потока
                threadID = Thread.CurrentThread.ManagedThreadId;
                try {  
                    // выполнить задание
                    this.client.ThreadProc((IBackgroundTask)sender, e); 
                }
                finally { threadID = 0; }
            }; 
            // указать используемые обработчики
            worker.ProgressChanged    += OnProgressChanged; 
            worker.RunWorkerCompleted += OnCompleted;
        }
        // освободить выделенные ресурсы
        protected override void OnDispose()
        {
            // освободить выделенные ресурсы
            worker.Dispose(); RefObject.Release(client); base.OnDispose(); 
        }
        // обработка уведомлений о прогрессе 
        private void OnProgressChanged(object sender, ProgressChangedEventArgs e)
        {
            // обработать сообщение
            if (handler != null) handler.OnProgressChanged(this, e);
        }
        // обработка уведомления о завершении
        private void OnCompleted(object sender, RunWorkerCompletedEventArgs e)
        {
            // обработать сообщение
            if (handler != null) handler.OnCompleted(this, e);
        }
        // обработчик событий
        public IBackgroundHandler LocalHandler { get { return handler; }}
        // идентификатор выполняемого потока
        public int ThreadID { get { return threadID; }}  

        // признак выполнения
        public bool IsBusy { get { return worker.IsBusy; }} 
        // признак наличия отмены
        public bool CancellationPending { get { return worker.CancellationPending; }}

        // запустить задание
        public void Start(object argument) { worker.RunWorkerAsync(argument); }
        // отменить задание
        public void Cancel() { worker.CancelAsync(); }

        // указать прогресс операции
        public void ReportProgress(int percentProgress, object userState)
        {
            // указать прогресс операции
            worker.ReportProgress(percentProgress, userState); 
        }
    }
}
