using System;
using System.Net.Sockets;

namespace Aladdin.Net.TCP
{
    ///////////////////////////////////////////////////////////////////////////
    // Сервер TCP
    ///////////////////////////////////////////////////////////////////////////
    public class Server : Net.Server
    {
        // используемое соединение и способ сериализации 
        private Socket socket; private IO.Serialization serialization; 

        // конструктор
        public Server(int maxConnections, IO.Serialization serialization)

            // сохранить переданные параметры
            : this(0, maxConnections, serialization) {}

        // конструктор
        public Server(int port, int maxConnections, IO.Serialization serialization)
        {
            // сохранить переданные параметры
            this.serialization = serialization; 

            // создать точку соединения
            socket = LocalHost.Bind(SocketType.Stream, ProtocolType.Tcp, port); 

            // начать прослушивание
            try { socket.Listen(maxConnections); } catch { socket.Close(); throw; }
        }
        // освободить выделенные ресурсы
        protected override void OnDispose() { socket.Close(); base.OnDispose(); } 

		///////////////////////////////////////////////////////////////////////
        // Получить сообщение
		///////////////////////////////////////////////////////////////////////
        public override Net.Conversation Accept(TimeSpan? timeout)
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

                // проверить наличие доступных подключений
                if (!socket.Poll(microSeconds, SelectMode.SelectRead)) return null; 
            }
            // дождаться соединения клиента
            return new Conversation(socket.Accept(), serialization); 
        }
        ///////////////////////////////////////////////////////////////////////
        // Закрыть диалог и оповестить клиента
        ///////////////////////////////////////////////////////////////////////
        public override void End(Net.Conversation conversation)
        {
            // закрыть диалог и оповестить клиента
            ((Conversation)conversation).End();
        } 
        public override void End(Net.Conversation conversation, Exception exception) 
        {
            // закрыть диалог и оповестить клиента
            ((Conversation)conversation).End(exception);
        } 
    }
}
