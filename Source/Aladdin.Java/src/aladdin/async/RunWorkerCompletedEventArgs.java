package aladdin.async;

///////////////////////////////////////////////////////////////////////////////
// Provides data for the Completed event
///////////////////////////////////////////////////////////////////////////////
public class RunWorkerCompletedEventArgs extends AsyncCompletedEventArgs
{
    // конструктор
    public RunWorkerCompletedEventArgs(Object result, Throwable error, boolean cancelled) 
    { 
        // сохранить переданные параметры
        super(error, cancelled, null); this.result = result; 
    }
    // получить результат
    public final Object result() { return result; } private final Object result;
}
