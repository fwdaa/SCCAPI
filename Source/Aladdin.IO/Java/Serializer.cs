using System; 

namespace Aladdin.IO.Java
{
    ///////////////////////////////////////////////////////////////////////////
    // Запись/чтение данных в формате Java
    ///////////////////////////////////////////////////////////////////////////
    public class Serializer : IO.Serializer
    {
        // способ сериализации
        private Serialization serialization; 

        // конструктор
        public Serializer(Serialization serialization)
        { 
            // сохранить переданные параметры
            this.serialization = serialization; 
        } 
        // раскодировать объект
        public override object Decode(byte[] encoded)
        {
            // раскодировать объект
            return serialization.Decode(encoded); 
        }
        // закодировать объект
        public override byte[] Encode(object obj)
        {
            // закодировать объект
            return serialization.Encode(obj); 
        }
    }
}
