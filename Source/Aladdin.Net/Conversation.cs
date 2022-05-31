using System;

namespace Aladdin.Net
{
    ///////////////////////////////////////////////////////////////////////////
    // Диалог взаимодействия
    ///////////////////////////////////////////////////////////////////////////
    public abstract class Conversation : Disposable
    {
        // признак закрытия диалога
        public abstract bool Inactive { get; }		

        // создать способ записи/чтения данных
        public abstract Serializer GetSerializer(Type type); 

        // признак завершения диалога
        public virtual bool IsEndDialog(Message message) { return false; } 

        // передать сообщение
        public void Send(object type, object value, TimeSpan? timeout)
        {
            // определить тип данных
            Type classType = (value != null) ? value.GetType() : null; 
        
            // получить способ сериализации данных
            Serializer serializer = GetSerializer(classType); 
        
            // закодировать и передать сообщение
            Send(serializer.Encode(type, value), timeout); 
        }
		// передать сообщение
        public abstract void Send(Message message, TimeSpan? timeout); 		
        // получить сообщение
        public abstract Message Receive(TimeSpan? timeout); 

        // раскодировать сообщение
        public object Decode(Message message, Type type)
        {
            // проверить наличие сообщения
            if (message == null) return null; 
        
            // получить способ сериализации данных
            Serializer serializer = GetSerializer(type); 
        
            // раскодировать сообщение
            return serializer.Decode(message); 
        }
        // раскодировать исключение
        public abstract Exception DecodeException(Message message); 
    }
}
