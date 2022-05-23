package aladdin.remoting;
import aladdin.*; 
import java.io.*;

///////////////////////////////////////////////////////////////////////////
// Объект управления удаленным потоком
///////////////////////////////////////////////////////////////////////////
public class RemoteClientControl extends RefObject
{
    // удаленный поток
    private final IBackgroundTask task; 
    
    // конструктор
    public RemoteClientControl(IBackgroundTask task) 
    {     
        // сохранить переданные параметры
        this.task = RefObject.addRef(task); 
    } 
    // освободить выделенные ресурсы
    @Override protected void onClose() throws IOException
    { 
        // освободить выделенные ресурсы
        RefObject.release(task); super.onClose(); 
    }
    // идентификатор запущенного потока
    public final long threadID() { return task.isBusy() ? task.threadID() : 0; }
    // признак запущенного потока
    public final boolean isRunning() { return threadID() != 0; }

    // запустить задание
    public final void start() throws Exception { task.start(this);  }
    // отменить задание
    public void cancel() throws IOException { task.cancel(); }
}
