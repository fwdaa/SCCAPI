using System;

namespace Aladdin.IO
{
    ///////////////////////////////////////////////////////////////////////////
    // Создание сериализаций данных
    ///////////////////////////////////////////////////////////////////////////
    public abstract class Serialization
    {
        // создать способ записи/чтения данных
        public abstract Serializer GetSerializer(Type type); 
    }
}
