package aladdin.async;

///////////////////////////////////////////////////////////////////////////////
// Tracks the lifetime of an asynchronous operation
///////////////////////////////////////////////////////////////////////////////
public final class AsyncOperation 
{
    // контекст синхронизации
    private final SynchronizationContext syncContext; 
    // дополнительные данные и признак завершения операции
    private final Object userSuppliedState; private boolean alreadyCompleted;

    // конструктор
    protected AsyncOperation(Object userSuppliedState, SynchronizationContext syncContext)
    {
        // сохранить переданные параметры
        this.userSuppliedState = userSuppliedState; this.alreadyCompleted = false;
        
        // указать начало операции
        this.syncContext = syncContext; syncContext.operationStarted();
    }
    // деструктор
    @Override protected void finalize() throws Throwable 
    {
        // для незавершенной операции 
        if (!alreadyCompleted && syncContext != null)
        {
            // завершить операцию
            syncContext.operationCompleted(); 
        }
        super.finalize(); 
    }    
    // дополнительные данные
    public final Object userSuppliedState() { return userSuppliedState; }

    // выполнить ассинхронный вызов 
    public final void post(SendOrPostCallback callback, Object arg)
    {
        // проверить отсутствие завершения операции
        if (alreadyCompleted) throw new IllegalStateException(); 
        
        // проверить указание обработчика
        if (callback == null) throw new NullPointerException(); 
        
        // передать сообщение обработчику
        syncContext.post(callback, arg);
    }
    public final void operationCompleted()
    {
        // проверить отсутствие завершения операции
        if (alreadyCompleted) throw new IllegalStateException(); 
        try {
            // завершить операцию
            syncContext.operationCompleted();
        }
        // указать признак завершения
        finally { alreadyCompleted = true; }
    }
    // выполнить ассинхронный вызов
    public final void postOperationCompleted(
        SendOrPostCallback callback, Object arg)
    {
        // выполнить ассинхронный вызов
        post(callback, arg); 
        try {
            // завершить операцию
            syncContext.operationCompleted();
        }
        // указать признак завершения
        finally { alreadyCompleted = true; }
    }
}
