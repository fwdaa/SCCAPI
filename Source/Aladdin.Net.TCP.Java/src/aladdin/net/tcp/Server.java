package aladdin.net.tcp;
import aladdin.net.*;
import java.io.*; 
import java.net.*; 

///////////////////////////////////////////////////////////////////////////
// Сервер TCP
///////////////////////////////////////////////////////////////////////////
public class Server extends aladdin.net.Server
{
    // используемое соединение и способ сериализации 
    private final ServerSocket socket; private final aladdin.io.Serialization serialization; 
    
    // конструктор
    public Server(int maxConnections, aladdin.io.Serialization serialization) throws IOException
    {
        // сохранить переданные параметры
        this(0, maxConnections, serialization); 
    }
    // конструктор
    public Server(int port, int maxConnections, aladdin.io.Serialization serialization) throws IOException
    {
        // сохранить способ сериализации
        this.serialization = serialization; 
        
        // создать точку соединения
        socket = LocalHost.bind(port, maxConnections); 
    }
    // освободить выделенные ресурсы
    @Override public void onClose() 
    { 
        // освободить выделенные ресурсы
        try { socket.close(); super.onClose(); } 
        
        // обработать возможную ошибку
        catch (IOException e) { throw new RuntimeException(e); } 
    }
    ///////////////////////////////////////////////////////////////////////
    // Получить сообщение
    ///////////////////////////////////////////////////////////////////////
    @Override
    public Conversation accept(int timeout) throws IOException
    {
        // указать величину тайм-аута
        if (timeout == 0) socket.setSoTimeout(1);
        else { 
            // указать величину тайм-аута
            socket.setSoTimeout(timeout > 0 ? timeout : 0); 
        }
        try { 
            // дождаться соединения клиента
            Socket clientSocket = socket.accept(); 

            // создать объект клиента
            return new Conversation(clientSocket, serialization); 
        }
        // обработать возможное исключение
        catch (InterruptedIOException e) { return null; }
    }
    ///////////////////////////////////////////////////////////////////////
    // Закрыть диалог и оповестить сервер
    ///////////////////////////////////////////////////////////////////////
    @Override public void end(
        aladdin.net.Conversation conversation) throws IOException 
    {
        // закрыть диалог и оповестить сервер
        ((Conversation)conversation).end();
    } 
    @Override public void end(aladdin.net.Conversation conversation, 
        Throwable exception) throws IOException 
    {
        // закрыть диалог и оповестить сервер
        ((Conversation)conversation).end(exception);
    }
    ///////////////////////////////////////////////////////////////////////
    // Идентификатор процесса, использующего порт
    ///////////////////////////////////////////////////////////////////////
    public int getClientProcess(aladdin.net.Conversation conversation) throws IOException
    {
        // идентификатор процесса, использующего порт
        return ((Conversation)conversation).remotePort(); 
    }
}
