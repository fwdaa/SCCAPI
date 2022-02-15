namespace Aladdin.CAPI.Software
{
    ///////////////////////////////////////////////////////////////////////////
    // Источник каталогов
    ///////////////////////////////////////////////////////////////////////////
    public interface IDirectoriesSource
    {
        // перечислить каталоги
        string[] EnumerateDirectories();
        
        // добавить каталог
        void AddDirectory(string directory); 
        // удалить каталог
        void RemoveDirectory(string directory); 
    }
}
