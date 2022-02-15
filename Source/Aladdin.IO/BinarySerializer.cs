using System;

namespace Aladdin.IO
{
    ///////////////////////////////////////////////////////////////////////
    // Сериализация бинарных данных
    ///////////////////////////////////////////////////////////////////////
    public class BinarySerializer : Serializer
    {
        // раскодировать объект
        public override object Decode(byte[] encoded) { return encoded; }

        // закодировать объект
        public override byte[] Encode(object obj)
        {
            // проверить тип объекта
            if (obj is byte[]) return (byte[])obj; 

            // при ошибке выбросить исключение
            throw new NotSupportedException(); 
        }
    }
}
