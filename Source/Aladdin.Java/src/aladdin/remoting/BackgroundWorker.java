package aladdin.remoting;
import aladdin.*; 
import aladdin.async.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Задание, выполняемое удаленно
///////////////////////////////////////////////////////////////////////////
public final class BackgroundWorker extends RefObject implements IBackgroundTask
{
    // объект управления заданием
    private final aladdin.async.BackgroundWorker worker; 
    // функция задания и идентификатор потока
    private final RemoteClient client; private long threadID; 
    // обработчик событий
    private final IBackgroundHandler handler; 

    // конструктор
    public BackgroundWorker(RemoteClient client, IBackgroundHandler handler)
    {
        // сохранить переданные параметры
        BackgroundWorker obj = this; this.handler = handler; 
        
        // увеличить счетчик ссылок
        this.client = RefObject.addRef(client);
        
        // создать объект управления заданием
        worker = new aladdin.async.BackgroundWorker(handler) {
            
            // основная функция потока, выполняемая удаленно
            @Override protected void doWork(DoWorkEventArgs e) throws Exception
            {
                // сохранить идентификатор потока
                threadID = Thread.currentThread().getId();

                // выполнить задание
                try { client.run(obj, e); } finally { threadID = 0; }
            }
        }; 
        // указать свойства задания
        worker.workerReportsProgress     (true); 
        worker.workerSupportsCancellation(true); 
    }
    // освободить выделенные ресурсы
    @Override protected void onClose() throws IOException
    { 
        // освободить выделенные ресурсы
        worker.close(); RefObject.release(client); super.onClose(); 
    }
    // обработчик событий
    @Override public final IBackgroundHandler localHandler() { return handler; } 
    // идентификатор выполняемого потока
    @Override public final long threadID() { return threadID; }  
    
    // признак выполнения
    @Override public final boolean isBusy() { return worker.isBusy(); } 
    // признак наличия отмены
    @Override public final boolean cancellationPending()
    { 
        // признак наличия отмены
        return worker.cancellationPending();
    }
    // запустить задание
    @Override public final void start(Object argument) throws Exception 
    { 
        // запустить задание
        worker.runWorkerAsync(argument); 
    }
    // указать прогресс операции
    @Override public final void reportProgress(int percentProgress, Object userState)
    {
        // указать прогресс операции
        worker.reportProgress(percentProgress, userState); 
    }
    // отменить задание
    @Override public final void cancel() { worker.cancelAsync(); }
}
