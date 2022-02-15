package aladdin.async;

///////////////////////////////////////////////////////////////////////////////
// Represents a method to be called when a message is to be dispatched to a synchronization context
///////////////////////////////////////////////////////////////////////////////
public interface SendOrPostCallback 
{
    // обработать сообщение
    void run(Object state) throws Exception;
}
