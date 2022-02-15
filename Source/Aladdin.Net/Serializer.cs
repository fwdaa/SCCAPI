namespace Aladdin.Net
{
    ///////////////////////////////////////////////////////////////////////////
    // Сериализация данных
    ///////////////////////////////////////////////////////////////////////////
    public abstract class Serializer 
    {
        // закодировать объект
        public abstract Message Encode(object type, object value); 
        // раскодировать объект
        public abstract object Decode(Message message); 
    }
}
