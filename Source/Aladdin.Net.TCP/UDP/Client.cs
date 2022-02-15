using System; 
using System.Net;
using System.Net.Sockets;

namespace Aladdin.Net.UDP
{
    ///////////////////////////////////////////////////////////////////////////    
    // Клиент UDP
    ///////////////////////////////////////////////////////////////////////////    
    public sealed class Client : Disposable
    {
        // используемое соединение
        private Socket socket; 

        // конструктор
        public Client(RemoteHost serverHost, int serverPort)
        {
            // выполнить соединение
            socket = serverHost.Connect(serverPort, SocketType.Dgram, ProtocolType.Udp); 
        }
        // закрыть соединение
        protected override void OnDispose() { socket.Close(); base.OnDispose(); }

		// передать сообщение
        public void Send(byte[] message, TimeSpan? timeout)
        {
            // при отсутствии времени ожидания
            if (timeout.HasValue && timeout.Value.Ticks == 0) socket.Blocking = false;

            // указать режим ожидания
            else { socket.Blocking = true;

                // указать бесконечное ожидание
                if (!timeout.HasValue) socket.SendTimeout = -1;

                // указать величину тайм-аута
                else socket.SendTimeout = (int)timeout.Value.TotalMilliseconds; 
            }
			// передать сообщение
			socket.Send(message);
        }
    }
}
