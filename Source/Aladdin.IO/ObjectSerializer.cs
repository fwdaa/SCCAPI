using System;
using System.IO;

namespace Aladdin.IO
{
    ///////////////////////////////////////////////////////////////////////////
    // Сериализация данных
    ///////////////////////////////////////////////////////////////////////////
    public abstract class ObjectSerializer : Serializer
    {
        // прочитать объект из потока
        public abstract object Read(Stream stream);

        // записать объект в поток
        public abstract void Write(object obj, Stream stream);

        // раскодировать объект
        public override object Decode(byte[] encoded)
        {
            // проверить наличие данных
            if (encoded.Length == 0) return null; 

            // создать поток
            using (MemoryStream stream = new MemoryStream(encoded))
            {
                // раскодировать объект
                return Read(stream);
            }
        }
        // закодировать объект
        public override byte[] Encode(object obj)
        {
            // проверить указание объекта
            if (obj == null) return new byte[0]; 

            // создать поток
            using (MemoryStream stream = new MemoryStream())
            {
                // закодировать объект
                Write(obj, stream); return stream.ToArray(); 
            }
        }
    }
}
