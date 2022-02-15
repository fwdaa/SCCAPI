package aladdin.capi.software;
import aladdin.*;
import aladdin.capi.*; 
import aladdin.io.xml.*;
import java.io.*;
import java.util.*;
import org.w3c.dom.*;

///////////////////////////////////////////////////////////////////////////
// Хранилище каталогов в файле конфигурации
///////////////////////////////////////////////////////////////////////////
public class ConfigDirectories implements IDirectoriesSource
{
	// имя файла конфигурации и модель документа
	private final String configFile; private Document document; 

    // конструктор
	public ConfigDirectories(Scope scope, String configName)
	{ 
        // получить профиль пользователя
        String directory = scope.equals(Scope.SYSTEM) ? 
            OS.INSTANCE.getSharedFolder() : OS.INSTANCE.getUserFolder(); 

        // указать полный путь к файлу
        configFile = String.format("%1$s%2$s%3$s", directory, File.separator, configName); 
        try {
            // при наличии файла
            File file = new File(configFile); if (!file.exists())
            {
                // прочитать модель документа
                document =  DOM.readDocument(configFile); 
            }
            // при отсутствии файла создать пустой документ
            if (document == null) document = DOM.createDocument("configuration"); 
        }
        catch (Throwable e) {} 
    }  
    // перечислить каталоги
    @Override public String[] enumerateDirectories()
    {
        // проверить поддержку операции
        if (document == null) return new String[0]; 
        
        // получить элемент для каталогов
        NodeList directoriesNodes = document.getElementsByTagName("directories");
        
        // проверить наличие элемента
        if (directoriesNodes.getLength() == 0) return new String[0]; 
        
        // создать список каталогов
        List<String> directories = new ArrayList<String>(); 
        
        // для всех каталогов
        for (Element element : DOM.readElements(directoriesNodes.item(0))) 
        try {
            // добавить каталог в список
            directories.add(element.getNodeValue());
        }
        // вернуть список каталогов
        catch (Throwable e) {} return directories.toArray(new String[directories.size()]); 
    }
    // добавить каталог
    @Override public void addDirectory(String directory) throws IOException
    {
        // проверить поддержку операции
        if (document == null) throw new UnsupportedOperationException(); 
        
        // получить элемент для каталогов
        NodeList directoriesNodes = document.getElementsByTagName("directories"); 
            
        // при отсутствии элемента
        Element directoriesNode = null; if (directoriesNodes.getLength() == 0)
        {
            // создать новый элемент
            directoriesNode = document.createElement("directories"); 
            
            // добавить элемент в документ
            document.getDocumentElement().appendChild(directoriesNode); 
        }
        // сохранить элемент для каталогов
        else { directoriesNode = (Element)directoriesNodes.item(0); }
        
        // создать новый элемент
        Element directoryNode = document.createElement("directory"); 

        // добавить элемент в документ
        directoriesNode.appendChild(directoryNode); 

        // указать путь к каталогу
        directoryNode.setNodeValue(directory); 
        
        // сохранить документ
        DOM.writeDocument(document, configFile);
    }
    // удалить каталог
    @Override public void removeDirectory(String directory) throws IOException
    {
        // проверить поддержку операции
        if (document == null) throw new UnsupportedOperationException(); 
        
        // получить элемент для каталогов
        NodeList directoriesNodes = document.getElementsByTagName("directories"); 
            
        // при отсутствии элемента
        Element directoriesNode = null; if (directoriesNodes.getLength() == 0)
        {
            // создать новый элемент
            directoriesNode = document.createElement("directories"); 
            
            // добавить элемент в документ
            document.getDocumentElement().appendChild(directoriesNode); 
        }
        // сохранить элемент для каталогов
        else { directoriesNode = (Element)directoriesNodes.item(0); }
        
        // для всех каталогов
        for (Element element : DOM.readElements(directoriesNode)) 
        {
            // сравнить имена каталогов
            if (directory.equals(element.getNodeValue())) 
            { 
                // удалить элемент 
                directoriesNode.removeChild(element); 

                // записать документ
                DOM.writeDocument(document, configFile); break; 
            }
        }
    }
}
