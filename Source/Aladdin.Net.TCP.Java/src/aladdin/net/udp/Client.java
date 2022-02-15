package aladdin.net.udp;
import aladdin.net.*; 
import aladdin.*; 
import java.io.*; 
import java.net.*;

///////////////////////////////////////////////////////////////////////////    
// Клиент UDP
///////////////////////////////////////////////////////////////////////////    
public class Client extends Disposable
{
	// коммуникационный сокет
	private final DatagramSocket socket; 

    // конструктор
    public Client(RemoteHost serverHost, int serverPort) throws IOException
    {
        // создать соединение
        socket = serverHost.connectDatagram(serverPort);
    }
    // закрыть соединение
    @Override protected void onClose() throws IOException
    { 
        // закрыть соединение
        socket.close(); super.onClose(); 
    }
    // передать сообщение
    public void send(byte[] message) throws IOException
    {
		// передать данные
		socket.send(new DatagramPacket(message, message.length, 
            socket.getInetAddress(), socket.getPort()
        ));
    }
}
