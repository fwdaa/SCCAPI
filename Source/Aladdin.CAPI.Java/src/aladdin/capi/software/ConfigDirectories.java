package aladdin.capi.software;
import aladdin.*;
import aladdin.capi.*; 
import aladdin.io.xml.*;
import java.io.*;
import java.util.*;

///////////////////////////////////////////////////////////////////////////
// Хранилище каталогов в файле конфигурации
///////////////////////////////////////////////////////////////////////////
public class ConfigDirectories implements IDirectoriesSource
{
	// модель документа
	private XmlKey document; 

    // конструктор
	public ConfigDirectories(Scope scope, String configName)
	{ 
        // получить профиль пользователя
        String directory = scope.equals(Scope.SYSTEM) ? 
            OS.INSTANCE.getSharedFolder() : OS.INSTANCE.getUserFolder(); 

        // указать полный путь к файлу
        String configFile = String.format(
            "%1$s%2$s%3$s", directory, File.separator, configName
        ); 
        try {
            // при отсутствии файла
            File file = new File(configFile); if (!file.exists()) 
            {
                // создать документ
                document = XmlKey.createDocument(configFile, "configuration"); 
            }
            // открыть документ
            else document = XmlKey.openDocument(configFile, "rw"); 
        }
        // обработать возможное исключение
        catch (Throwable e) {}
    }  
    // перечислить каталоги
    @Override public String[] enumerateDirectories()
    {
        // проверить поддержку операции
        if (document == null) return new String[0]; 
        
        // создать список каталогов
        List<String> directories = new ArrayList<String>(); 
        
        // получить элемент для каталогов
        XmlKey key = document.openKey("directories", "r"); 
             
        // проверить наличие элемента
        if (key == null) return new String[0]; 

        // для всех каталогов
        for (XmlKey child : key.enumerateKeys("r"))
        {
            // добавить каталог в список
            directories.add(child.getValue());
        }
        // вернуть список каталогов
        return directories.toArray(new String[directories.size()]); 
    }
    // добавить каталог
    @Override public void addDirectory(String directory) throws IOException
    {
        // проверить поддержку операции
        if (document == null) throw new UnsupportedOperationException(); 
        
        // получить элемент для каталогов
        XmlKey key = document.openOrCreateKey("directories"); 
             
        // добавить новый элемент 
        XmlKey child = key.createKey("directory"); 

        // указать содержимое элемента
        child.setValue(directory); 
    }
    // удалить каталог
    @Override public void removeDirectory(String directory) throws IOException
    {
        // проверить поддержку операции
        if (document == null) throw new UnsupportedOperationException(); 
        
        // получить элемент для каталогов
        XmlKey key = document.openKey("directories", "rw"); 

        // проверить наличие элемента
        if (key == null) return; 

        // для всех каталогов
        for (XmlKey child : key.enumerateKeys("r"))
        {
            // проверить совпадение значения 
            if (!child.getValue().equals(directory)) continue; 
                
            // удалить каталог
            key.deleteKey(child); break; 
        }
    }
}
