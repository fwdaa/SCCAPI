using System; 

namespace Aladdin.Net
{
    ///////////////////////////////////////////////////////////////////////////
    // Создание сериализаций данных
    ///////////////////////////////////////////////////////////////////////////
    public abstract class Serialization 
    {
        // создать способ записи/чтения данных
        public abstract Serializer GetSerializer(Type type); 

        // закодировать сообщение
        public Message Encode(object type, object value)
        {
            // определить тип данных
            Type classType = (value != null) ? value.GetType() : null; 
        
            // получить способ сериализации данных
            Serializer serializer = GetSerializer(classType); 
        
            // закодировать сообщение
            return serializer.Encode(type, value); 
        }
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
    }
}
