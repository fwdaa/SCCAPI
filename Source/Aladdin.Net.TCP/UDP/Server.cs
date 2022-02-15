using System;
using System.Net.Sockets;

namespace Aladdin.Net.UDP
{
    ///////////////////////////////////////////////////////////////////////////    
    // Сервер UDP
    ///////////////////////////////////////////////////////////////////////////    
    public sealed class Server : Disposable
    {
	    // коммуникационный сокет и буфер для приема
	    private Socket socket; private byte[] buffer; 

        // конструктор
        public Server(int maxLength) : this(0, maxLength) {}
        // конструктор
        public Server(int port, int maxLength) 
        {
            // создать точку соединения
            socket = LocalHost.Bind(SocketType.Dgram, ProtocolType.Udp, port); 

            // указать максимальный размер пакета
            buffer = new byte[maxLength];  socket.ReceiveBufferSize = buffer.Length; 
        }
        // освободить выделенные ресурсы
        protected override void OnDispose() { socket.Close(); base.OnDispose(); } 

        // принять сообщение
        public byte[] Receive(TimeSpan? timeout) 
        {
            // при отсутствии указания времени ожидания
            if (timeout.HasValue && timeout.Value.Ticks == 0)
            {
                // проверить наличие данных
                if (socket.Available == 0) return null; socket.Blocking = false; 
            }
            // указать режим ожидания
            else { socket.Blocking = true; 

                // указать величину тайм-аута
                int microSeconds = (timeout.HasValue) ? (int)timeout.Value.Ticks / 10 : Int32.MaxValue; 

                // проверить наличие сообщения
                if (!socket.Poll(microSeconds, SelectMode.SelectRead)) return null; 
            }
		    // принять сообщение
		    return Arrays.CopyOf(buffer, socket.Receive(buffer)); 
        }
    }
}
