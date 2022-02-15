using System;

namespace Aladdin.CAPI.SCard
{
    ///////////////////////////////////////////////////////////////////////////
    // Каталог файловой системы апплета
    ///////////////////////////////////////////////////////////////////////////
    public interface IAppletFileFolder : IAppletFileObject
    {
        // список объектов файловой системы
        UInt16[] EnumerateFolders(); UInt16[] EnumerateFiles(); 

        // создать объект файловой системы
        IAppletFileFolder CreateFolder(UInt16 name, FileObjectInfo info); 
        IAppletFile       CreateFile  (UInt16 name, FileObjectInfo info); 

        // открыть объект файловой системы
        IAppletFileFolder OpenFolder(UInt16 name); IAppletFile OpenFile(UInt16 name);

        // удалить объект файловой системы
		void RemoveFolder(UInt16 name); void RemoveFile(UInt16 name);
    }
}
