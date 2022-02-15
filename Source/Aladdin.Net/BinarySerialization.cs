using System;

namespace Aladdin.Net
{
    ///////////////////////////////////////////////////////////////////////
    // Сериализация бинарных данных
    ///////////////////////////////////////////////////////////////////////
    public class BinarySerialization<T> : Serialization
    {
        // создание сериализаций данных
        private IO.Serialization serialization; 
        
        // конструктор
        public BinarySerialization(IO.Serialization serialization)
        {
            // сохранить переданные параметры
            this.serialization = serialization; 
        }
        // создать способ записи/чтения данных
        public override Serializer GetSerializer(Type type)
        {
            // проверить необходимость данных
            if (type == null) return new BinarySerializer<T>(null); 
        
            // создать способ записи/чтения бинарных данных
            if (type == typeof(byte[])) return new BinarySerializer<T>(); 
            
            // вернуть способ сериализации
            return new BinarySerializer<T>(serialization.GetSerializer(type)); 
        }
    }
}
