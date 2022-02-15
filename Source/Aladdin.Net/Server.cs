using System;
using System.Diagnostics;
using System.Collections.Generic;

namespace Aladdin.Net
{
    ///////////////////////////////////////////////////////////////////////////
    // Сервер сеанса взаимодействия
    ///////////////////////////////////////////////////////////////////////////
    public abstract class Server : Client
    {
        // процедура обработки сообщений для сервера
        public void MessageProcedure(Handler handler, TimeSpan? serverTimeout)
        {
            // определить текущее время
            for (DateTime lastTime = DateTime.Now; ; lastTime = DateTime.Now)
            try { 
                // список активных соединений
                List<Conversation> conversations = new List<Conversation>();
 
                // список отложенных сообщений
                List<Message> messages = new List<Message>(); 
        
                // дождаться соединения клиента
                Conversation conversation = Accept(serverTimeout);   
            
                // определить разницу во времени
                TimeSpan delta = DateTime.Now - lastTime; 
                
                // обработать период простоя
                if (delta >= serverTimeout) handler.OnIdle(this, delta);
                
                // проверить наличие соединения
                if (conversation == null) continue; lastTime = DateTime.Now; 
            
                // добавить соединение в список
                conversations.Add(conversation); messages.Add(null); 

                // при наличии активных соединений
                for (; conversations.Count != 0; lastTime = DateTime.Now)
                {            
                    // создать копию активных соединений
                    List<Conversation> activeConversations = new List<Conversation>(conversations); 

                    // создать копию отложенных сообщений
                    List<Message> activeMessages = new List<Message>(messages); 

                    // сбросить список активных соединений
                    conversations.Clear(); messages.Clear();
                
                    // для всех активных соединений
                    for (int i = 0; i < activeConversations.Count; i++, lastTime = DateTime.Now)
                    {
                        // проверить наличие соединения
                        conversation = activeConversations[i]; if (conversation.Closed) { continue; } 
                    
                        // при отсутствии отложенного сообщения
                        Message message = activeMessages[i]; bool delayed = true; if (message == null) 
                        { 
                            // проверить наличие нового сообщения
                            try { message = conversation.Receive(new TimeSpan(0)); } catch { continue; }
                    
                            // определить разницу во времени
                            delta = DateTime.Now - lastTime; delayed = false; 
                
                            // обработать период простоя
                            if (delta >= serverTimeout) handler.OnIdle(this, delta);
                        }
                        // проверить наличие сообщения
                        if (message == null) messages.Add(null); 

                        // обработать сообщение
                        else messages.Add(handler.Dispatch(conversation, message, delayed) ? null : message);  

                        // сохранить активный диалог
                        conversations.Add(conversation); 
                    }
                    // проверить наличие нового соединения
                    conversation = Accept(new TimeSpan(0)); delta = DateTime.Now - lastTime; 
                
                    // обработать период простоя
                    if (delta >= serverTimeout) handler.OnIdle(this, delta);
                
                    // при наличии соединения нового клиента
                    if (conversation != null)
                    {
                        // добавить соединение в список
                        conversations.Add(conversation); messages.Add(null); 
                    }
                }
            }
            // обработать завершение и исключение
            catch (Handler.InterruptedException) { break; } catch (Exception e) { Log(e); }
        }
        // дождаться соединения клиента
        public abstract Conversation Accept(TimeSpan? timeout); 

        // закрыть диалог и оповестить клиента
        public override void End(Conversation conversation)
        {
            // операция не реализована
            throw new NotImplementedException(); 
        }
        // закрыть диалог и оповестить клиента
        public override void End(Conversation conversation, Exception exception)
        {
            // операция не реализована
            throw new NotImplementedException(); 
        }
        // запись в журнал
        public virtual void Log(Exception e) 
        { 
            // выполнить запись в журнал
            try { Log("FAIL", e.StackTrace, e.Message); } catch {}
        }
        // запись в журнал
        public virtual void Log(string type, string msg)
        {
            // проверить тип сообщения
            string caller = String.Empty; if (type.Equals("FAIL")) 
            {
                // получить стековый фрейм вызова функции
                StackTrace stackTrace = new StackTrace(true); 
            
                // указать вызывающую функцию
                if (stackTrace.FrameCount >= 2) caller = stackTrace.GetFrame(1).ToString(); 
            }
            // выполнить запись в журнал
            try { Log(type, caller, msg); } catch {}
        }
        // выполнить запись в журнал
        protected virtual void Log(string type, string caller, string msg) {} 
    }
}
