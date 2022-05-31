package aladdin.net;
import aladdin.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////
// Обработчик сообщений на стороне сервера
///////////////////////////////////////////////////////////////////////
public abstract class Handler extends Disposable
{
    // конструктор
    public Handler(Server server) 
    
        // сохранить переданные параметры
        { this.server = server; } private final Server server;

    // процедура обработки
    public final void messageProcedure(int serverTimeout) throws Exception
    {
        // обработать начало процедуры
        onBegin(server); 
        
        // процедура обработки
        try { server.messageProcedure(this, serverTimeout); }
        
        // обработать завершение процедуры
        finally { onEnd(server); }
    }
    // обработать начало и завершение
    protected void onBegin(Server server) throws Exception {}
    protected void onEnd  (Server server)                  {}

    // обработать тайм-аут
    public void onIdle(Server server, long timeout) throws InterruptedException {}
    
    // выполнить диспетчеризацию сообщений
    public final boolean dispatch(Conversation conversation, 
        Message message, boolean delayed) throws InterruptedException
    {
        // при отсутствии сообщения
        if (message == null) 
        {
            // выбросить исключение тайм-аута
            try { throw new InterruptedIOException(); } catch (Throwable e) 
            {
                // обработать исключение 
                onServerException(server, conversation, e); 
            
                // закрыть диалог с оповещением клиента
                endDialog(conversation, e); 
            }
        } 
        // при завершении диалога без ошибок
        else if (conversation.isEndDialog(message))
        {
            // завершить диалог без оповещения клиента
            cleanupDialog(conversation); 
        }
        else { Throwable exception; 
            
            // раскодировать исключение
            try { exception = conversation.decodeException(message); }
            
            // обработать возможную ошибку
            catch (Throwable e) { exception = e; }
            
            // при наличии исключения
            if (exception != null) 
            {
                // обработать исключение клиента
                onClientException(server, conversation, exception); 
                
                // завершить диалог без оповещения клиента
                cleanupDialog(conversation); 
            }
            else { 
                // обработать сообщение
                try { return onMessage(server, conversation, message, delayed); }

                // обработать прерывание обработки сообщений
                catch (InterruptedException e) 
                { 
                    // закрыть диалог с оповещением клиента
                    endDialog(conversation); throw e; 
                } 
                // обработать возможную ошибку
                catch (Throwable e) 
                { 
                    // обработать исключение 
                    onServerException(server, conversation, e); 
            
                    // закрыть диалог с оповещением клиента
                    endDialog(conversation, e); return true; 
                }
            }
        }
        return true;         
    }
    // закрыть диалог и оповестить клиента
    public final void endDialog(Conversation conversation) throws InterruptedException
    { 
        // закрыть диалог с оповещением клиента
        try { server.end(conversation); } catch (Throwable e) {} 
    }
    // закрыть диалог с оповещением клиента
    public void endDialog(Conversation conversation, Throwable exception) throws InterruptedException
    {
        // закрыть диалог с оповещением клиента
        try { server.end(conversation, exception); } catch (Throwable e) {} 
    }
    // закрыть диалог без оповещения клиента
    public final void cleanupDialog(Conversation conversation) throws InterruptedException
    {
        // завершить диалог без оповещения клиента
        try { conversation.close(); } catch (Throwable e) {}
    }
    // обработать сообщение
    protected abstract boolean onMessage(Server server, 
        Conversation conversation, Message message, boolean delayed) throws Exception; 
    
    // обработать исключение на сервере
    protected void onServerException(Server server, 
        Conversation conversation, Throwable e) { server.log(e); }
    // обработать исключение на клиенте
    protected void onClientException(Server server, 
        Conversation conversation, Throwable e) {}
}
