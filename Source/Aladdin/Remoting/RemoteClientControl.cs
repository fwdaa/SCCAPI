namespace Aladdin.Remoting
{
    ///////////////////////////////////////////////////////////////////////////
    // Объект управления удаленным потоком
    ///////////////////////////////////////////////////////////////////////////
    public class RemoteClientControl : RefObject
    {
        // конструктор
        public RemoteClientControl(IBackgroundTask task) 
        
            // сохранить переданные параметры
            { this.task = task; } private readonly IBackgroundTask task; 

        // освободить выделенные ресурсы
        protected override void OnDispose() 
        { 
            // освободить выделенные ресурсы
            task.Dispose(); base.OnDispose(); 
        }
        // идентификатор запущенного потока
        public int ThreadID { get { return task.IsBusy ? task.ThreadID : 0; }}
        // признак запущенного потока
        public bool IsBusy { get { return ThreadID != 0; }}

        // запустить задание
        public void Start() { task.Start(this);  }
        // отменить задание
        public virtual void Cancel() { task.Cancel(); }
    }
}
