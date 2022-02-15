package aladdin.async;

///////////////////////////////////////////////////////////////////////////////
// Provides data for a cancelable event
///////////////////////////////////////////////////////////////////////////////
public class CancelEventArgs
{
    // конструктор
    public CancelEventArgs(boolean cancel) { this.cancel = cancel; }
    // конструктор
    public CancelEventArgs() { this(false); } public boolean cancel;
}
