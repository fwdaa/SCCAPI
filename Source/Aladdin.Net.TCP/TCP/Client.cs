using System; 
using System.Net; 
using System.Net.Sockets; 

namespace Aladdin.Net.TCP
{
    ///////////////////////////////////////////////////////////////////////////
    // Клиент TCP
    ///////////////////////////////////////////////////////////////////////////
    public class Client : Net.Client
    {
        // точка соединения и способ сериализации данных
        private IPEndPoint endPoint; private IO.Serialization serialization;

        // конструктор
        public Client(RemoteHost serverHost, int serverPort, IO.Serialization serialization)
        {
            // сохранить переданные параметры
            this.serialization = serialization; 

            // выполнить соединение
            using (Socket socket = serverHost.Connect(
                serverPort, SocketType.Stream, ProtocolType.Tcp))
            { 
                // сохранить точку соединения
                endPoint = (IPEndPoint)socket.RemoteEndPoint;
            }
        }
		///////////////////////////////////////////////////////////////////////
		// Создать диалог
		///////////////////////////////////////////////////////////////////////
		public Net.Conversation BeginConversation()
        {
            // указать тип соединения
            Socket socket = new Socket(endPoint.AddressFamily, SocketType.Stream, ProtocolType.Tcp); 

            // выполнить соединение
            try { socket.Connect(endPoint.Address, endPoint.Port); } catch { socket.Close(); throw; }

            // создать диалог
            return new Conversation(socket, serialization);
        }
        ///////////////////////////////////////////////////////////////////////
        // Закрыть диалог и оповестить сервер
        ///////////////////////////////////////////////////////////////////////
        public override void End(Net.Conversation conversation)
        {
            // закрыть диалог и оповестить сервер
            ((Conversation)conversation).End();
        } 
        public override void End(Net.Conversation conversation, Exception exception) 
        {
            // закрыть диалог и оповестить сервер
            ((Conversation)conversation).End(exception);
        } 
    }
}
