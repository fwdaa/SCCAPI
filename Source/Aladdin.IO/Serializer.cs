namespace Aladdin.IO
{
    ///////////////////////////////////////////////////////////////////////////
    // Сериализация данных
    ///////////////////////////////////////////////////////////////////////////
    public abstract class Serializer
    {
        // раскодировать объект
        public abstract object Decode(byte[] encoded); 

        // закодировать объект
        public abstract byte[] Encode(object obj); 
    }
}
