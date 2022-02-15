package aladdin.net;
import java.io.*;
import java.net.*;

///////////////////////////////////////////////////////////////////////////
// Локальный хост
///////////////////////////////////////////////////////////////////////////
public abstract class LocalHost
{
    ///////////////////////////////////////////////////////////////////////////
    // TCP
    ///////////////////////////////////////////////////////////////////////////
    @SuppressWarnings({"try"}) 
    public static int findPort(int minPort, int maxPort) throws IOException
    {
        // для всех портов из диапазона
        IOException exception = null; for (int port = minPort; port <= maxPort; port++)
        {
            // создать точку соединения
            try (ServerSocket socket = bind(port, 50)) { return port; }
        
            // обработать возможную ошибку
            catch (IOException e) { exception = e; } 
        }
        throw exception;
    }
    // создать точку соединения
    public static ServerSocket bind(int port, int maxConnections) throws IOException
    {
        // создать точку соединения
        return new ServerSocket(port, maxConnections); 
    }
    ///////////////////////////////////////////////////////////////////////////
    // UDP
    ///////////////////////////////////////////////////////////////////////////
    @SuppressWarnings({"try"}) 
    public static int findDatagramPort(int minPort, int maxPort) throws IOException
    {
        // для всех портов из диапазона
        IOException exception = null; for (int port = minPort; port <= maxPort; port++)
        {
            // создать точку соединения
            try (DatagramSocket socket = bindDatagram(port)) { return port; }
        
            // обработать возможную ошибку
            catch (IOException e) { exception = e; } 
        }    
        throw exception;
    }
    // создать точку соединения
    public static DatagramSocket bindDatagram(int port) throws IOException
    {
        // создать точку соединения
        return new DatagramSocket(port); 
    }
}
