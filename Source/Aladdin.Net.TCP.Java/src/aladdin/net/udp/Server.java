package aladdin.net.udp;
import aladdin.net.*;
import aladdin.*;
import java.io.*;
import java.net.*;
import java.util.*;

///////////////////////////////////////////////////////////////////////////    
// Сервер UDP
///////////////////////////////////////////////////////////////////////////    
public class Server extends Disposable
{
	// коммуникационный сокет и пакет для приема сообщений
	private final DatagramSocket socket; private final DatagramPacket inpacket;

    // конструктор
    public Server(int maxLength) throws IOException { this(0, maxLength); }
    
    // конструктор
    public Server(int port, int maxLength) throws IOException
    {
        // создать точку соединения
        byte[] buffer = new byte[maxLength]; socket = LocalHost.bindDatagram(port); 
        
        // указать максимальный размер пакета
        socket.setReceiveBufferSize(buffer.length);
        
		// создать пакет для приема сообщений
		inpacket = new DatagramPacket(buffer, buffer.length);
    }
    // закрыть соединение
    @Override protected void onClose() throws IOException
    { 
        // закрыть соединение
        socket.close(); super.onClose(); 
    }
    // принять сообщение
    public byte[] receive(int timeout) throws IOException
    {
        // указать величину тайм-аута
        if (timeout == 0) socket.setSoTimeout(500);
        else { 
            // указать величину тайм-аута
            socket.setSoTimeout(timeout > 0 ? timeout : 0); 
        }
        // принять сообщение
        try { socket.receive(inpacket); 

            // вернуть сообщение
            return Arrays.copyOf(inpacket.getData(), inpacket.getLength()); 
        }
        // обработать возможное исключение
        catch (InterruptedIOException e) { return null; }
    }
}
