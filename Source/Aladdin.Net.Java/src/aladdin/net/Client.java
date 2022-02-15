package aladdin.net;
import aladdin.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Клиент сеанса взаимодействия
///////////////////////////////////////////////////////////////////////////
public class Client extends Disposable
{ 
	// получить сообщение для клиента
    public Message receive(Conversation conversation, int timeout) throws Throwable
    {
        // получить сообщение
        Message message = conversation.receive(timeout);

        // при отсутствии сообщения
        if (message == null) 
        { 
            // выбросить исключение тайм-аута
            try { throw new InterruptedIOException(); } catch (Throwable e) 
            { 
                // завершить диалог с оповещением сервера
                end(conversation, e); throw e; 
            }
        }
        // при завершении диалога выполнить очистку
        else if (conversation.isEndDialog(message)) conversation.close(); 
        
        else { Throwable exception; 
            
            // раскодировать исключение
            try { exception = conversation.decodeException(message); }
            
            // обработать возможную ошибку
            catch (Throwable e) { exception = e; }
            
            // при наличии исключения выполнить очистку
            if (exception != null) { conversation.close(); throw exception; }
        }
        return message; 
    }
    // закрыть диалог и оповестить сервер
    public void end(Conversation conversation) throws IOException {} 
    // закрыть диалог и оповестить сервер
    public void end(Conversation conversation, Throwable exception) throws IOException {} 
}
