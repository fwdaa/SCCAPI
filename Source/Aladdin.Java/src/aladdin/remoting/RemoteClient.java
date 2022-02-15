package aladdin.remoting;
import aladdin.*; 
import aladdin.async.*; 

///////////////////////////////////////////////////////////////////////////
// Удаленный поток
///////////////////////////////////////////////////////////////////////////
public abstract class RemoteClient extends RefObject
{
    // создать объект управления потоком клиента
    public final RemoteClientControl start(IBackgroundHandler handler) throws Exception
    {
        // создать объект управления потоком
        try (IBackgroundTask task = new BackgroundWorker(this, handler))  
        {  
            // создать объект управления потоком
            try (RemoteClientControl control = createRemoteControl(task)) 
            {  
                // запустить поток
                control.start(); return RefObject.addRef(control); 
            }
        }
    }
    // создать объект управления потоком клиента
    protected RemoteClientControl createRemoteControl(IBackgroundTask task) throws Exception
    {
        // создать объект управления потоком клиента
        return new RemoteClientControl(task); 
    }
    // функция удаленного потока 
    public abstract void run(IBackgroundTask task, DoWorkEventArgs args) throws Exception; 
}
