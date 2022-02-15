using System;
using System.Text;
using System.IO;
using System.Net.Sockets;

namespace Aladdin.Net.TCP
{
	///////////////////////////////////////////////////////////////////////////
	// Диалог TCP
	///////////////////////////////////////////////////////////////////////////
	public class Conversation : Net.Conversation
	{
        // используемый сокет и способ сериализации данных
        private Socket socket; private Serialization serialization;

		// конструктор
		internal Conversation(Socket socket, IO.Serialization serialization)
        {
            // указать размер буфера для приема сообщений
            this.socket = socket; socket.ReceiveBufferSize = 65536; 

            // указать способ сериализации данных
            this.serialization = new BinarySerialization<Int32>(serialization); 
        }
		// выполнить освобождение ресурсов
        protected override void OnDispose() 
        { 
		    // выполнить освобождение ресурсов
            if (socket.Connected) socket.Close(); base.OnDispose(); 
        }
        // признак закрытия диалога
        public override bool Closed { get { return !socket.Connected; }}

        // создать способ записи/чтения данных
        public override Serializer GetSerializer(Type type)
        {
            // создать способ записи/чтения данных
            return serialization.GetSerializer(type); 
        }
	    ///////////////////////////////////////////////////////////////////////
        // Управление диалогом
	    ///////////////////////////////////////////////////////////////////////
        public override bool IsEndDialog(Message message)
        {
            // признак завершения диалога
            return message.Type.Equals(0); 
        }
        public override Exception DecodeException(Message message)
        {
            // проверить тип сообщения 
            if (message == null || !message.Type.Equals(-1)) return null; 

            // извлечь содержимое сообщения
            byte[] body = ((BinaryMessage<Int32>)message).Body; 

            // раскодировать исключение
            return SerialException.FromString(Encoding.UTF8.GetString(body)); 
        }
        public void End(Exception exception) 
        {
            // проверить указание исключения
            if (exception == null) { End(); return; } 
            
            // проверить закрытие соединения
            if (Closed) return; TimeSpan timeout = new TimeSpan(0); 
        
	        // закодировать исключение
            string error = SerialException.ToString(exception, false); 
        
            // передать сообщение о завершении
            Send(-1, Encoding.UTF8.GetBytes(error), timeout); Close();
        }
        public void End()
        {
            // проверить закрытие соединения
            if (Closed) return; TimeSpan timeout = new TimeSpan(0); 
            
            // передать сообщение о завершении
            Send(0, new byte[0], timeout); Close();
        }
		///////////////////////////////////////////////////////////////////////
		// Передать сообщение
		///////////////////////////////////////////////////////////////////////
		public override void Send(Message message, TimeSpan? timeout)		
        {
            // выполнить преобразование типа
            BinaryMessage<Int32> binaryMessage = (BinaryMessage<Int32>)message; 

            // указать тип и содержимое сообщения
            int type = (int)binaryMessage.Type; byte[] body = binaryMessage.Body;

            // проверить наличие данных
            if (body == null) body = new byte[0]; 

            // выделить память для представления
            byte[] encoded = new byte[8 + body.Length]; 

            // закодировать общий размер  
            encoded[0] = (byte)((encoded.Length      ) & 0xFF); 
            encoded[1] = (byte)((encoded.Length >>  8) & 0xFF); 
            encoded[2] = (byte)((encoded.Length >> 16) & 0xFF); 
            encoded[3] = (byte)((encoded.Length >> 24) & 0xFF); 

            // закодировать тип данных
            encoded[4] = (byte)((type      ) & 0xFF); 
            encoded[5] = (byte)((type >>  8) & 0xFF); 
            encoded[6] = (byte)((type >> 16) & 0xFF); 
            encoded[7] = (byte)((type >> 24) & 0xFF); 

            // скопировать тело сообщения
            Array.Copy(body, 0, encoded, 8, body.Length); 
            
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
            socket.Send(encoded);
		}
		///////////////////////////////////////////////////////////////////////
        // Получить сообщение
		///////////////////////////////////////////////////////////////////////
		public override Message Receive(TimeSpan? timeout)
        {
            // при отсутствии времени ожидания
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
            // выделить буфер для размера и типа
            byte[] encoded = new byte[8]; int length = 0; int type = 0; 
            
            // прочитать размер и тип данных 
            int size = socket.Receive(encoded); if (size != encoded.Length) throw new InvalidDataException();

            // раскодировать размер и тип данных
            length |= ((encoded[0] & 0xFF)      ) | ((encoded[1] & 0xFF) <<  8); 
            length |= ((encoded[2] & 0xFF) << 16) | ((encoded[3] & 0xFF) << 24); 
            type   |= ((encoded[4] & 0xFF)      ) | ((encoded[5] & 0xFF) <<  8); 
            type   |= ((encoded[6] & 0xFF) << 16) | ((encoded[7] & 0xFF) << 24); 

            // выделить буфер требуемого размера
            if (length < 8) throw new InvalidDataException(); byte[] body = new byte[length - 8]; 

            // прочитать данные
            size = socket.Receive(body); if (size != body.Length) throw new InvalidDataException(); 

            // вернуть сообщение
            return new BinaryMessage<Int32>(type, body); 
        }
    }
}
