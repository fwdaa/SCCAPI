using System;

namespace Aladdin.Net
{
    ///////////////////////////////////////////////////////////////////////
    // Обработчик сообщений на стороне сервера
    ///////////////////////////////////////////////////////////////////////
    public abstract class Handler : Disposable
    {
        // конструктор
        public Handler(Server server) 
        
            // сохранить переданные параметры
            { this.server = server; } private Server server;

        // признак завершения обработки сообщений
        [Serializable] public class InterruptedException : ApplicationException {};

        // процедура обработки
        public void MessageProcedure(TimeSpan? serverTimeout)
        {
            // обработать начало процедуры
            OnBegin(server); 

            // процедура обработки
            try { server.MessageProcedure(this, serverTimeout); }

            // обработать завершение процедуры
            finally { OnEnd(server); }
        }
        // обработать начало и завершение
        protected virtual void OnBegin(Server server) {}
        protected virtual void OnEnd  (Server server) {}

        // обработать тайм-аут
        public virtual void OnIdle(Server server, TimeSpan timeout) {}
    
        // выполнить диспетчеризацию сообщений
        public bool Dispatch(Conversation conversation, Message message, bool delayed)
        {
            // проверить наличие сообщения
            if (message == null) try { throw new TimeoutException(); } catch (Exception e) 
            { 
                // обработать исключение 
                OnServerException(server, conversation, e); 
            
                // закрыть диалог с оповещением клиента
                EndDialog(conversation, e); 
            }
            // при завершении диалога без ошибок
            else if (conversation.IsEndDialog(message))
            {
                // завершить диалог без оповещения клиента
                CleanupDialog(conversation); 
            }
            else { Exception exception = null; 

                // раскодировать исключение
                try { exception = conversation.DecodeException(message); } 

                // обработать возможную ошибку
                catch (Exception e) { server.Log(e); exception = e; }

                // при наличии исключения
                if (exception != null)
                {
                    // обработать исключение клиента
                    OnClientException(server, conversation, exception); 
                
                    // завершить диалог без оповещения клиента
                    CleanupDialog(conversation); 
                }
                else { 
                    // обработать сообщение
                    try { return OnMessage(server, conversation, message, delayed); }

                    // обработать прерывание обработки сообщений
                    catch (InterruptedException) 
                    { 
                        // закрыть диалог с оповещением клиента
                        EndDialog(conversation); throw; 
                    } 
                    // обработать возможную ошибку
                    catch (Exception e) 
                    { 
                        // обработать исключение 
                        OnServerException(server, conversation, e); 
            
                        // закрыть диалог с оповещением клиента
                        EndDialog(conversation, e); 
                    }
                }
            }
            return true; 
        }
        // закрыть диалог и оповестить клиента
        public void EndDialog(Conversation conversation) 
        { 
            // закрыть диалог и оповестить клиента
            EndDialog(conversation, null); 
        }
        // закрыть диалог и оповестить клиента
        public void EndDialog(Conversation conversation, Exception exception)
        {
            // закрыть диалог с оповещением клиента
            try { server.End(conversation, exception); } catch {} 
        }
        // закрыть диалог без оповещения клиента
        public void CleanupDialog(Conversation conversation)
        {
            // завершить диалог без оповещения клиента
            try { conversation.Close(); } catch {} 
        }
        // обработать сообщение
        protected abstract bool OnMessage(Server server, 
            Conversation conversation, Message message, bool delayed
        );
        // обработать исключение на сервере
        protected virtual void OnServerException(Server server, 
            Conversation conversation, Exception e) { server.Log(e); }
        // обработать исключение на клиенте
        protected virtual void OnClientException(Server server, 
            Conversation conversation, Exception e) {}
    }
}
