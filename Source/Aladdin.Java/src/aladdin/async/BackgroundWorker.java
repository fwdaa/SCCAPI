package aladdin.async;
import aladdin.remoting.*; 
import java.io.*;

///////////////////////////////////////////////////////////////////////////////
// Executes an operation on a separate thread
///////////////////////////////////////////////////////////////////////////////
public abstract class BackgroundWorker implements Closeable
{
    // обработчик событий
   private final IBackgroundHandler handler; 
    
    // возможность отмены потока и наличия информации прогресса
    private boolean canCancelWorker; private boolean workerReportsProgress;
    // ассинхронная операция и признак отмены операции
    private AsyncOperation asyncOperation; private boolean cancellationPending; 
    
    // функции для удаленного вызова 
    private final SendOrPostCallback operationCompleted;
    private final SendOrPostCallback progressReporter;

    // конструктор
    public BackgroundWorker(IBackgroundHandler handler)
    {
        // указать начальные условия 
        this.handler = handler; asyncOperation = null; cancellationPending = false; 
        
        // указать значения по умолчанию
        canCancelWorker = false; workerReportsProgress = false; 
        
        // создать делегат
        progressReporter = new SendOrPostCallback() 
        { 
            @Override public void run(Object state) throws Exception
            {
                // обработать событие прогресса
                onProgressChanged((ProgressChangedEventArgs) state);
            }
        }; 
        // создать делегат
        operationCompleted = new SendOrPostCallback() 
        { 
            @Override public void run(Object state) throws Exception
            {
                // указать завершение потока
                asyncOperation = null; cancellationPending = false;
                
                // обработать событие прогресса
                onRunWorkerCompleted((RunWorkerCompletedEventArgs) state);
            }
        }; 
    }
    // освободить выделенные ресурсы
    @Override public void close() {}

    // получить возможность отмены потока
    public final boolean workerSupportsCancellation() { return canCancelWorker; }
    // установить возможность отмены потока
    public final void workerSupportsCancellation(boolean value) { canCancelWorker = value; }
    
    // получить наличие информации прогресса
    public final boolean workerReportsProgress() { return workerReportsProgress; }
    // установить наличие информации прогресса
    public final void workerReportsProgress(boolean value) { workerReportsProgress = value; }
    
    // признак отмены операции
    public final boolean cancellationPending() { return cancellationPending; }
    // признак выполнения потока
    public final boolean isBusy() { return asyncOperation != null; }
    
    // отменить операцию 
    public final void cancelAsync()
    {
        // установить признак отмены
        if (!canCancelWorker) throw new IllegalStateException(); cancellationPending = true;
    }
    // обработать событие прогресса
    protected void onProgressChanged(ProgressChangedEventArgs e) throws Exception
    {
        // обработать событие прогресса
        if (handler != null) handler.onProgressChanged(this, e);
    }
    // обработать событие завершения 
    protected void onRunWorkerCompleted(RunWorkerCompletedEventArgs e) throws Exception
    {
        // обработать событие завершения 
        if (handler != null) handler.onCompleted(this, e);
    }
    ///////////////////////////////////////////////////////////////////////////
    // Функции, выполняемые в удаленном потоке
    ///////////////////////////////////////////////////////////////////////////
    
    // указать прогресс операции
    public final void reportProgress(int percentProgress)
    {
        // указать прогресс операции
        reportProgress(percentProgress, null);
    }
    // указать прогресс операции
    public final void reportProgress(int percentProgress, Object userState)
    {
        // проверить наличие информации прогресса
        if (!workerReportsProgress) throw new IllegalStateException();
        
        // указать информацию прогресса
        ProgressChangedEventArgs changedEventArgs = 
            new ProgressChangedEventArgs(percentProgress, userState);
        
        // передать информацию прогресса
        asyncOperation.post(progressReporter, changedEventArgs);
    }
    // запустить удаленный поток
    public final void runWorkerAsync() throws Exception { runWorkerAsync(null); }

    // запустить удаленный поток
    public final void runWorkerAsync(Object argument) throws Exception
    {
        // проверить корректность операции 
        if (asyncOperation != null) throw new IllegalStateException();
      
        // создать ассинхронную операцию
        cancellationPending = false; asyncOperation = AsyncOperationManager.createOperation(null); 
        
        // создать объект удаленного потока
        Thread thread = new Thread() 
        {
            // основная функция потока, выполняемая удаленно
            @Override public void run() { threadStart(argument);  }
        }; 
        // запустить поток
        thread.start();
    }
    // основная функция потока, выполняемая удаленно
    protected abstract void doWork(DoWorkEventArgs e) throws Exception;
    
    // основная функция удаленного потока
    private void threadStart(Object argument)
    {
        // указать начальные условия 
        Object result = null; Throwable error = null; boolean cancelled = false;
        try {
            // выполнить основную функцию
            DoWorkEventArgs e = new DoWorkEventArgs(argument); doWork(e);
            
            // проверить наличие отмены и результат операции
            if (e.cancel) cancelled = true; else result = e.result;
        }
        // сохранить возникшее исключение
        catch (Throwable exception) { error = exception; }
        
        // указать результат
        Object state = new RunWorkerCompletedEventArgs(result, error, cancelled); 
        
        // вернуть результат
        asyncOperation.postOperationCompleted(operationCompleted, state);
    }
}
