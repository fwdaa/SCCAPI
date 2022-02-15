package aladdin.async;

///////////////////////////////////////////////////////////////////////////////
// Provides concurrency management for classes that support asynchronous method calls
///////////////////////////////////////////////////////////////////////////////
public final class AsyncOperationManager 
{
    // текущий контекст синхронизации
    public static SynchronizationContext synchronizationContext = new SynchronizationContext(); 
    
    // создать ассинхронный вызов 
    public static AsyncOperation createOperation(Object userSuppliedState) 
    {
        // создать ассинхронный вызов 
        return new AsyncOperation(userSuppliedState, synchronizationContext); 
    }
}
