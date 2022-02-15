package aladdin.net;
import aladdin.*;
import java.io.*; 
import java.util.*; 

///////////////////////////////////////////////////////////////////////////
// Сервера сеанса взаимодействия
///////////////////////////////////////////////////////////////////////////
public abstract class Server extends Client
{
    // процедура обработки сообщений для сервера
    public final void messageProcedure(Handler handler, int serverTimeout) throws IOException
    {
        // определить текущее время
        for (long lastTime = new Date().getTime(); ; lastTime = new Date().getTime())
        try { 
            // список активных соединений
            List<Conversation> conversations = new ArrayList<Conversation>(); 
            
            // список отложенных сообщений
            List<Message> messages = new ArrayList<Message>(); 
        
            // дождаться соединения клиента
            Conversation conversation = accept(serverTimeout);   
            
            // определить разницу во времени
            long delta = new Date().getTime() - lastTime; 
                
            // обработать период простоя
            if (delta >= serverTimeout) handler.onIdle(this, delta);
                
            // проверить наличие соединения
            if (conversation == null) continue; lastTime = new Date().getTime(); 
            
            // добавить активное соединение в список
            conversations.add(conversation); messages.add(null); 
            
            // при наличии активных соединений
            for (; !conversations.isEmpty(); lastTime = new Date().getTime())            
            {
                // создать копию активных соединений
                List<Conversation> activeConversations = new ArrayList<Conversation>(conversations); 
                
                // создать копию отложенных сообщений
                List<Message> activeMessages = new ArrayList<Message>(messages); 

                // сбросить список активных соединений
                conversations.clear(); messages.clear();
                
                // для всех активных соединений
                for (int i = 0; i < activeConversations.size(); i++, lastTime = new Date().getTime())
                {
                    // проверить наличие соединения
                    conversation = activeConversations.get(i); if (conversation.closed()) continue; 
                    
                    // при отсутствии отложенного сообщения
                    Message message = activeMessages.get(i); boolean delayed = true; if (message == null) 
                    {
                        // проверить наличие нового сообщения
                        try { message = conversation.receive(0); } catch (Throwable e) { continue; }
                        
                        // определить разницу во времени
                        delta = new Date().getTime() - lastTime; delayed = false; 
                
                        // обработать период простоя
                        if (delta >= serverTimeout) handler.onIdle(this, delta);
                    }
                    // проверить наличие сообщения
                    if (message == null) messages.add(null); 

                    // обработать сообщение
                    else messages.add(handler.dispatch(conversation, message, delayed) ? null : message);  
                        
                    // сохранить активный диалог
                    conversations.add(conversation); 
                }
                // проверить наличие нового соединения
                conversation = accept(0); delta = new Date().getTime() - lastTime;
                
                // обработать период простоя
                if (delta >= serverTimeout) handler.onIdle(this, delta);
                
                // при наличии соединения нового клиента
                if (conversation != null)
                {
                    // добавить соединение в список
                    conversations.add(conversation); messages.add(null); 
                }
            }
        }
        // обработать завершение 
        catch (InterruptedException e) { break; } catch (Throwable e) {}
    }    
    // дождаться соединения клиента
    public abstract Conversation accept(int timeout) throws IOException; 
    
    // закрыть диалог и оповестить клиента
    @Override public void end(Conversation conversation) throws IOException
    {
        // операция не реализована
        throw new UnsupportedOperationException(); 
    }
    // закрыть диалог и оповестить клиента
    @Override public void end(Conversation conversation, Throwable exception) throws IOException
    {
        // операция не реализована
        throw new UnsupportedOperationException(); 
    }
    // запись в журнал
    public void log(String type, String msg) 
    {
        // получить информацию о вызове
        String stackTrace = type.equals("FAIL")? StackTrace.getFrame(1) : new String();
        
        // выполнить запись в журнал
        try { log(type, stackTrace, msg); } catch (Throwable e) {}
    }
    // запись в журнал
    public void log(Throwable e)
    {
        // получить описание исключения и стековый фрейм
        String description = e.toString(); String stackTrace = StackTrace.fromException(e); 
        
        // вывести информацию в журнал
        try { log("FAIL", stackTrace, description); } catch (Throwable ex) {}
    }
    // запись в журнал
    protected void log(String type, String caller, String msg) throws Exception {} 
    
}
