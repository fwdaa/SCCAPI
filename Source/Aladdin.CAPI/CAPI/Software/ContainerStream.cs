using System;

namespace Aladdin.CAPI.Software
{
    ///////////////////////////////////////////////////////////////////////////
    // Поток бинарных данных
    ///////////////////////////////////////////////////////////////////////////
    public abstract class ContainerStream : RefObject
    {
        // имя контейнера и уникальный идентификатор
        public abstract Object Name { get; } public abstract string UniqueID { get; }

        // прочитать/записать данные
        public abstract byte[] Read(); public abstract void Write(byte[] buffer); 
    }
}
