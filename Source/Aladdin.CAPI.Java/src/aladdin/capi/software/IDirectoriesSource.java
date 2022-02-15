package aladdin.capi.software;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Источник каталогов
///////////////////////////////////////////////////////////////////////////
public interface IDirectoriesSource
{
    // перечислить каталоги
    String[] enumerateDirectories();
    
    // добавить каталог
    void addDirectory(String directory) throws IOException; 
    // удалить каталог
    void removeDirectory(String directory) throws IOException; 
}
