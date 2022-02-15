using System;

namespace Aladdin.CAPI.SCard
{
    ///////////////////////////////////////////////////////////////////////////
    // Объект файловой системы
    ///////////////////////////////////////////////////////////////////////////
    public interface IAppletFileObject
    {
        // путь к объекту
        UInt16[] Path { get; } 

        // описание объекта
        FileObjectInfo GetInfo(); 
	}
}
