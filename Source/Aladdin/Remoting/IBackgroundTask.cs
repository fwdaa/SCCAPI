namespace Aladdin.Remoting
{
    ///////////////////////////////////////////////////////////////////////////
    // Задание, выполняемое удаленно
    ///////////////////////////////////////////////////////////////////////////
    public interface IBackgroundTask : IRefObject
    {
        // признак выполнения и идентификатор потока
        bool IsBusy { get; } int ThreadID { get; } 
        // признак отмены задания 
        bool CancellationPending { get; }

        // обработчик событий
        IBackgroundHandler LocalHandler { get; }

        // запустить и отменить задание
        void Start(object argument); void Cancel();

        // указать прогресс операции (для удаленного потока)
        void ReportProgress(int percentProgress, object userState);
    }
}
