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
    public sealed class BackgroundThread : RefObject, IBackgroundTask
    {
        // функция задания и апартаменты потока
        private readonly RemoteClient client; private readonly ApartmentState apartmentState;
        // обработчик событий и асинхронная операция
        private readonly IBackgroundHandler handler; private AsyncOperation asyncOperation; 
        // идентификатор потока и наличие отмены
        private int threadID; private bool cancellationPending; 

        // конструктор
        public BackgroundThread(RemoteClient client, ApartmentState apartmentState, IBackgroundHandler handler)
        {
            // сохранить переданные параметры
            this.client = RefObject.AddRef(client); this.apartmentState = apartmentState; 

            // инициализировать переменные             
            this.handler = handler; threadID = 0; asyncOperation = null; cancellationPending = false; 
        }
        // освободить выделенные ресурсы
        protected override void OnDispose() { RefObject.Release(client); base.OnDispose(); }

        // обработчик событий
        public IBackgroundHandler LocalHandler { get { return handler; }}
        // идентификатор выполняемого потока
        public int ThreadID { get { return threadID; }}  

        // признак выполнения
        public bool IsBusy { get { return asyncOperation != null; }}
        // признак наличия отмены
        public bool CancellationPending { get { return cancellationPending; }}

        // запустить задание
        public void Start(object argument)
        {
            // проверить отсутствие запуска
            if (IsBusy) throw new InvalidOperationException(); cancellationPending = false;

            // создать ассинхронную операцию
            asyncOperation = AsyncOperationManager.CreateOperation(null);

            // создать поток
            Thread thread = new Thread(WorkerThreadStart); 

            // при известном типе апартаментов
            if (apartmentState != ApartmentState.Unknown)
            {
                // установить апартаменты потока
                thread.SetApartmentState(apartmentState); 
            }
            // запустить поток
            thread.Start(argument); 
        }
        // функция потока
        private void WorkerThreadStart(object argument)
        {
            // указать начальные условия 
            object result = null; Exception error = null; bool cancelled = false;
            try {
                // указать идентификатор потока
                threadID = Thread.CurrentThread.ManagedThreadId; 

                // указать передаваемые параметры
                DoWorkEventArgs e = new DoWorkEventArgs(argument); 

                // выполнить функцию задания 
                client.ThreadProc(this, e); 
                
                // установить признак отмены
                if (e.Cancel) cancelled = true; else result = e.Result; 
            }
            // обработать возможное исключение
            catch (Exception exception) { error = exception; } threadID = 0; 

            // указать передаваемые параметры
            RunWorkerCompletedEventArgs completedEventArgs = 
                new RunWorkerCompletedEventArgs(result, error, cancelled); 

            // передать уведомление исходному потоку
            asyncOperation.PostOperationCompleted(
                AsyncOperationCompleted, completedEventArgs
            );
        }
        // функция уведомления 
        private void AsyncOperationCompleted(object arg)
        {
            // выполнить преобразование типа
            RunWorkerCompletedEventArgs completedEventArgs = (RunWorkerCompletedEventArgs)arg; 

            // указать завершение задания 
            asyncOperation = null; cancellationPending = false;

            // обработать завершение задания 
            if (handler != null) handler.OnCompleted(this, completedEventArgs);
        }
        // указать отмену операции 
        public void Cancel() { cancellationPending = true; }

        // указать прогресс операции
        public void ReportProgress(int percentProgress, object userState)
        {
            // проверить отсутствие запуска
            if (asyncOperation == null) return;

            // указать аргументы для события 
            ProgressChangedEventArgs changedEventArgs = 
                new ProgressChangedEventArgs(percentProgress, userState);

            // передать уведомление исходному потоку
            asyncOperation.Post(ProgressReporter, changedEventArgs);
        }
        // функция уведомления 
        private void ProgressReporter(object arg)
        {
            // выполнить преобразование типа
            ProgressChangedEventArgs changedEventArgs = (ProgressChangedEventArgs)arg; 

            // обработать изменение прогресса
            if (handler != null) handler.OnProgressChanged(this, changedEventArgs);
        }
    }
}
