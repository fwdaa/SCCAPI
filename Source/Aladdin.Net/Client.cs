using System;

namespace Aladdin.Net
{
    ///////////////////////////////////////////////////////////////////////////
    // Клиент сеанса взаимодействия
    ///////////////////////////////////////////////////////////////////////////
    public class Client : Disposable
    {
		// получить сообщение
        public Message Receive(Conversation conversation, TimeSpan? timeout)
        {
            // получить сообщение
            Message message = conversation.Receive(timeout);

            // при отсутствии сообщения
            if (message == null) try { throw new TimeoutException(); } catch (Exception e)
            {
                // завершить диалог с оповещением сервера
                End(conversation, e); throw;
            }
            // при завершении диалога выполнить очистку
            else if (conversation.IsEndDialog(message)) conversation.Dispose(); 

            else { Exception exception = null;

                // раскодировать исключение
                try { exception = conversation.DecodeException(message); }

                // обработать возможную ошибку
                catch (Exception e) { exception = e; }

                // при наличии исключения выполнить очистку
                if (exception != null) { conversation.Dispose(); throw exception; }
            }
            return message; 
        }
        // закрыть диалог и оповестить сервер
        public virtual void End(Conversation conversation) {} 
        // закрыть диалог и оповестить сервер
        public virtual void End(Conversation conversation, Exception exception) {} 
    }
}
