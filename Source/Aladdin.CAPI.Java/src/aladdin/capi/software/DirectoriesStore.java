package aladdin.capi.software;
import aladdin.capi.*; 
import java.io.*; 
import java.util.*; 

///////////////////////////////////////////////////////////////////////////
// Файловое хранилище программных контейнеров
///////////////////////////////////////////////////////////////////////////
public class DirectoriesStore extends SecurityStore
{
    // источник каталогов
    private final IDirectoriesSource directoriesSource;
    // каталоги и расширения файлов
    private final List<String> directories; private final String[] extensions; 

    // конструктор
	public DirectoriesStore(CryptoProvider provider, Scope scope, 
        IDirectoriesSource directoriesSource, String[] extensions) 
	{ 
        // сохранить переданные параметры
        super(provider, scope); this.extensions = extensions; 
        
        // сохранить переданные параметры
        this.directoriesSource = directoriesSource; 

        // создать список каталогов
        directories = new ArrayList<String>(); if (directoriesSource != null)
        { 
            // для всех каталогов
            for (String directory : directoriesSource.enumerateDirectories())
            try {
                // получить путь каталога
                String path = new File(directory).getCanonicalPath(); 
                
                // добавить каталог в список
                this.directories.add(path); 
            }
            // обработать возможную ошибку
            catch (IOException e) {}
        }
	}  
    // конструктор
	public DirectoriesStore(CryptoProvider provider, Scope scope, 
            
        // сохранить переданные параметры
        String[] directories, String[] extensions) 
	{ 
        // сохранить переданные параметры
        super(provider, scope); this.extensions = extensions; 
        
        // создать список каталогов
        this.directories = new ArrayList<String>(); directoriesSource = null; 
        
        // для всех каталогов
        for (String directory : directories)
        try {
            // получить путь каталога
            String path = new File(directory).getCanonicalPath(); 
                
            // добавить каталог в список
            this.directories.add(path); 
        }
        // обработать возможную ошибку
        catch (IOException e) {}
	}  
    // имя хранилища
    @Override public String name() { return "FILE"; }
    
	///////////////////////////////////////////////////////////////////////
	// Управление контейнерами
	///////////////////////////////////////////////////////////////////////
    @Override
    public String[] parseObjectName(String fullName)
    {
        // для всех каталогов списка
        for (String directory : this.directories)
        {
            // проверить совпадение имени каталога
            if (!fullName.startsWith(directory)) continue; 

            // проверить на точное совпадение
            if (fullName.length() == directory.length())
            {
                // вернуть разобранное имя
                return new String[] { directory }; 
            }
            // проверить совпадение имени каталога
            if (fullName.charAt(directory.length()) != '\\') continue; 

            // проверить на точное совпадение
            if (fullName.length() == directory.length() + 1)
            {
                // вернуть разобранное имя
                return new String[] { directory }; 
            }
            // извлечь имя файла
            String name = fullName.substring(directory.length() + 1); 

            // проверить отсутствие разделителей
            if (name.contains("\\")) continue; 
            
            // вернуть разобранное имя
            return new String[] { directory, name }; 
        }
        // при ошибке выбросить исключение
        throw new NoSuchElementException(); 
    }
    @Override
	public String[] enumerateObjects()
	{
        // создать список каталогов
        List<String> dirs = new ArrayList<String>(); 

        // для всех каталогов
        for (String directory : this.directories)
        {
            // при наличии каталога
            if (new File(directory).exists())
            {
                // добавить каталог в список
                dirs.add(directory); 
            }
        }
        // вернуть список каталогов
        return dirs.toArray(new String[dirs.size()]); 
	}
    @Override
	public SecurityObject createObject(IRand rand, 
        Object name, Object authenticationData, Object... parameters) throws IOException
    {
        // создать объект каталога
        File fileDir = new File(name.toString()).getCanonicalFile(); 
        
        // для всех каталогов
        for (String dir : directories)
        {
            // сравнить имена каталогов
            if (fileDir.compareTo(new File(dir)) != 0) continue; 
            
            // объект уже существует
            throw new IOException();
        }
        // получить имя каталога
        String directory = fileDir.getCanonicalPath(); 
        
        // при наличии источника каталогов
        if (directoriesSource != null)
        { 
            // добавить имя каталога
            directoriesSource.addDirectory(directory); 
        }
        // добавить имя каталога в список
        directories.add(directory);
        
        // вернуть объект каталога
        return new DirectoryStore(this, directory, extensions); 
    }
    @Override
	public SecurityObject openObject(Object name, String access) throws IOException
    {
        // создать объект каталога
        File fileDir = new File(name.toString()).getCanonicalFile(); 
        
        // для всех каталогов
        for (String dir : directories)
        {
            // сравнить имена каталогов
            if (fileDir.compareTo(new File(dir)) != 0) continue; 
            
            // получить имя каталога
            String directory = fileDir.getCanonicalPath(); 

            // вернуть объект каталога
            return new DirectoryStore(this, directory, extensions); 
        }
        // объект не найден
        throw new NoSuchElementException();
    }
    @Override
	public void deleteObject(Object name, Authentication[] authentications) throws IOException
    {
        // создать объект каталога
        File fileDir = new File(name.toString()).getCanonicalFile(); 
        
        // для всех каталогов
        for (String dir : directories)
        {
            // сравнить имена каталогов
            if (fileDir.compareTo(new File(dir)) != 0) continue; 

            // получить имя каталога
            String directory = fileDir.getCanonicalPath(); 
            
            // удалить каталог из списка
            directories.remove(directory); if (directoriesSource != null)
            try { 
                // удалить каталог
                directoriesSource.removeDirectory(directory); 
            } 
            catch (Throwable e) {} break; 
        }
        // вызвать базовую функцию
        super.deleteObject(name, authentications);
    }
}
