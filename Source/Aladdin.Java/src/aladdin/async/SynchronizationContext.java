package aladdin.async;

/////////////////////////////////////////////////////////////////////
// Контекст синхронизации
/////////////////////////////////////////////////////////////////////
public class SynchronizationContext 
{
    // обработка и завершение операции
    public void operationStarted() {} public void operationCompleted() {}
    
    // обработка синхронного сообщения
    public void send(SendOrPostCallback d, Object state) throws Exception { d.run(state); }
    // обработка ассинхронного сообщения
    public void post(SendOrPostCallback d, Object state)
    {
        // создать поток
        Thread thread = new Thread() { @Override public void run() 
        { 
            // вызвать целевой метод
            try { d.run(state); } catch (Throwable e) {}
        }}; 
        // запустить поток
        thread.start();  
    }
}
