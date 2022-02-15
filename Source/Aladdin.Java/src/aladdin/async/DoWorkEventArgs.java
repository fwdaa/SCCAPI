package aladdin.async;

///////////////////////////////////////////////////////////////////////////////
// Provides data for the BackgroundWorker.DoWork event handler
///////////////////////////////////////////////////////////////////////////////
public class DoWorkEventArgs extends CancelEventArgs
{
    // параметр и результат 
    public Object argument; public Object result;
    
    // конструктор
    public DoWorkEventArgs(Object argument)
    {
        // сохранить переданные параметры
        super(); this.argument = argument; this.result = null; 
    }
}
