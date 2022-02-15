package aladdin.async;
import java.lang.reflect.*; 

///////////////////////////////////////////////////////////////////////////////
// Provides data for the Completed event
///////////////////////////////////////////////////////////////////////////////
public class AsyncCompletedEventArgs 
{
    // исключение, признак отмены и дополнительные данные
    private final Throwable error; private final boolean cancelled; private final Object userState;
    
    // конструктор
    public AsyncCompletedEventArgs(Throwable error, boolean cancelled, Object userState)
    {
        // сохранить переданные параметры
        this.error = error; this.cancelled = cancelled; this.userState = userState;
    }    
    // получить исключение
    public final Throwable error  () { return error;     } 
    // получить признак отмены
    public final boolean cancelled() { return cancelled; } 
    // получить дополнительные данные
    public final Object userState () { return userState; } 
    
    // проверить возможность возвращения результата
    protected final void raiseExceptionIfNecessary() throws InvocationTargetException
    {
        // проверить отсутствие ошибок
        if (error != null) throw new InvocationTargetException(error);
        
        // проверить отсутствие отмены
        if (cancelled) throw new IllegalStateException();
    }
}
