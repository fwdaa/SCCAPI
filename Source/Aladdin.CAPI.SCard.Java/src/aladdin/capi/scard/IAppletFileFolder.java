package aladdin.capi.scard;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Каталог файловой системы апплета
///////////////////////////////////////////////////////////////////////////
public interface IAppletFileFolder extends IAppletFileObject
{
    // список объектов файловой системы
    short[] EnumerateFolders(); short[] EnumerateFiles(); 

    // создать объект файловой системы
    IAppletFileFolder createFolder(short name, FileObjectInfo info) throws IOException; 
    IAppletFile       createFile  (short name, FileObjectInfo info) throws IOException; 

    // открыть объект файловой системы
    IAppletFileFolder openFolder(short name) throws IOException; 
    IAppletFile       openFile  (short name) throws IOException;

    // удалить объект файловой системы
    void removeFolder(short name) throws IOException; 
    void removeFile  (short name) throws IOException;
}
