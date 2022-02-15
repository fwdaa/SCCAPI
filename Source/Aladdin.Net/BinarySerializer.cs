using System;
using System.IO;

namespace Aladdin.Net
{
    ///////////////////////////////////////////////////////////////////////
    // Сериализация бинарных данных
    ///////////////////////////////////////////////////////////////////////
    public class BinarySerializer<T> : Serializer
    {
        // способ сериализации
        private IO.Serializer serializer; 

        // конструктор
        public BinarySerializer() : this(new IO.BinarySerializer()) {} 
            
        // конструктор
        public BinarySerializer(IO.Serializer serializer)
        {
            // сохранить переданные параметры
            this.serializer = serializer; 
        }
        // закодировать объект
        public override Message Encode(object type, object value)
        {
            // проверить наличие объекта
            if (value == null) return new BinaryMessage<T>((T)type, new byte[0]); 

            // закодировать объект
            return new BinaryMessage<T>((T)type, serializer.Encode(value)); 
        }
        // раскодировать объект
        public override object Decode(Message message)
        {
            // получить содержимое объекта
            byte[] body = ((BinaryMessage<T>)message).Body; 
        
            // раскодировать объект
            if (serializer != null) return serializer.Decode(body); 
        
            // проверить допустимость отсутствия объекта
            if (body.Length == 0) return null; throw new InvalidDataException();
        }
    }
}
