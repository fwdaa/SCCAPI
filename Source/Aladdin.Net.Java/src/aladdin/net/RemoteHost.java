package aladdin.net;
import java.net.*;
import java.io.*;

///////////////////////////////////////////////////////////////////////////
// Удаленный хост
///////////////////////////////////////////////////////////////////////////
public class RemoteHost
{
    // список допустимых адресов
    private final InetAddress[] addressList; 

    // конструктор
    public RemoteHost(InetAddress[] addressList) { this.addressList = addressList; }

    // конструктор
    public RemoteHost(String hostName) throws UnknownHostException
    {
        // определить адреса
        this.addressList = InetAddress.getAllByName(hostName); 
    }
    // список допустимых адресов
    public final InetAddress[] addressList() { return addressList; } 
    
    ///////////////////////////////////////////////////////////////////////////
    // TCP
    ///////////////////////////////////////////////////////////////////////////
    public final Socket connect(int port) throws IOException
    {
        // для всех полученных адресов 
        IOException exception = null; for (InetAddress address : addressList)
        try {
            // указать способ создания сокета
            return new Socket(address, port); 
        }
        // обработать возможное исключение
        catch (IOException e) { if (exception == null) exception = e; } throw exception; 
    }
    ///////////////////////////////////////////////////////////////////////////
    // UDP
    ///////////////////////////////////////////////////////////////////////////
    public final DatagramSocket connectDatagram(int port) throws IOException
    {
        // открыть сокет
        DatagramSocket socket = new DatagramSocket(); 

        // для всех полученных адресов 
        Throwable exception = null; for (InetAddress address : addressList)
        try {
            // выполнить соединение
            socket.connect(address, port); return socket; 
        }
        // обработать возможное исключение
        catch (Throwable e) { if (exception == null) exception = e; } 
        
        // проверить отсутствие ошибок
        if (exception != null) socket.close(); throw new IOException(exception);
    }
}
