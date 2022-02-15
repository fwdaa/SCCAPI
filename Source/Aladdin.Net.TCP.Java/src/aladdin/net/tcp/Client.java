package aladdin.net.tcp;
import aladdin.net.*; 
import java.io.*; 
import java.net.*; 

///////////////////////////////////////////////////////////////////////////
// Клиент TCP
///////////////////////////////////////////////////////////////////////////
public class Client extends aladdin.net.Client
{
    // адрес хоста и номер порта
    private final InetAddress serverHost; private final int serverPort; 
    // способ сериализации данных
    private final aladdin.io.Serialization serialization;

    // конструктор
    public Client(RemoteHost serverHost, int serverPort, 
        aladdin.io.Serialization serialization) throws IOException
    {
        // выполнить соединение
        try (Socket socket = serverHost.connect(serverPort)) 
        {
            // сохранить точку соединения
            this.serverHost = socket.getInetAddress();
        }
        // сохранить переданные параметры
        this.serverPort = serverPort; this.serialization = serialization;
    }
    ///////////////////////////////////////////////////////////////////////
	// Создать диалог
	///////////////////////////////////////////////////////////////////////
	public Conversation beginConversation() throws IOException
    {
        // создать сеанс взаимодействия
        Socket socket = new Socket(serverHost, serverPort); 
        
        // создать диалог
        return new Conversation(socket, serialization); 
    }
    ///////////////////////////////////////////////////////////////////////
    // Закрыть диалог и оповестить клиента
    ///////////////////////////////////////////////////////////////////////
    @Override public void end(
        aladdin.net.Conversation conversation) throws IOException 
    {
        // закрыть диалог и оповестить клиента
        ((Conversation)conversation).end();
    } 
    @Override public void end(aladdin.net.Conversation conversation, 
        Throwable exception) throws IOException 
    {
        // закрыть диалог и оповестить клиента
        ((Conversation)conversation).end(exception);
    } 
}
