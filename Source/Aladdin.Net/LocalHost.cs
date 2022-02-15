using System;
using System.Net; 
using System.Net.Sockets; 

namespace Aladdin.Net
{
    ///////////////////////////////////////////////////////////////////////////
    // Локальный хост
    ///////////////////////////////////////////////////////////////////////////
    public static class LocalHost
    {
        // найти свободный порт
        public static int FindPort(SocketType socketType, ProtocolType protocolType, int minPort, int maxPort) 
        {
            // для всех портов из диапазона
            Exception exception = null; for (int port = minPort; port <= maxPort; port++)
            try {
                // создать точку соединения
                using (Socket socket = Bind(socketType, protocolType, port)) { return port; }
            }
            // обработать возможное исключение
            catch (Exception e) { exception = e; } throw exception;
        }
        // создать точку соединения
        public static Socket Bind(SocketType socketType, ProtocolType protocolType, int port)
        {
            // указать способ создания сокета
            Socket socket = new Socket(AddressFamily.InterNetwork, socketType, protocolType); 

            // указать используемый порт
            try { socket.Bind(new IPEndPoint(IPAddress.Any, port)); return socket; } 
                
            // обработать возможную ошибку
            catch { socket.Close(); socket = null; if (!Socket.OSSupportsIPv6) throw; }

            // указать способ создания сокета
            socket = new Socket(AddressFamily.InterNetworkV6, socketType, protocolType); 

            // указать используемый порт
            try { socket.Bind(new IPEndPoint(IPAddress.Any, port)); return socket; } 
                
            // обработать возможную ошибку
            catch { socket.Close(); socket = null; throw; }
        }
    }
}
