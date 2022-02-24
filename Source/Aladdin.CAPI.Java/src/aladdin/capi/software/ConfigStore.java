package aladdin.capi.software;
import aladdin.*;
import aladdin.capi.*; 
import aladdin.io.xml.*; 
import java.io.*;
import java.util.*; 

///////////////////////////////////////////////////////////////////////////
// Раздел файла конфигурации как хранилище программных контейнеров
///////////////////////////////////////////////////////////////////////////
public class ConfigStore extends ContainerStore
{
	// модель документа
	private XmlKey document; 

	// конструктор
	public ConfigStore(CryptoProvider provider, Scope scope, String configName) 
    {
        // сохранить переданные параметры
        super(provider, scope); document = null; 
        
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
    // имя хранилища
    @Override public Object name() 
    {
        // имя хранилища
        return scope().equals(Scope.SYSTEM) ? "FSLM" : "FSCU"; 
    }
    ///////////////////////////////////////////////////////////////////////
	// Управление контейнерами
	///////////////////////////////////////////////////////////////////////
	@Override public String[] enumerateObjects()
	{
        // проверить поддержку операции
        if (document == null) return new String[0]; 
        
        // создать список имен
        List<String> names = new ArrayList<String>(); 

        // получить элемент для контейнеров
        XmlKey key = document.openKey("containers", "r"); 
             
        // проверить наличие элемента
        if (key == null) return new String[0]; 

        // для всех каталогов
        for (XmlKey child : key.enumerateKeys("r"))
        {
            // добавить каталог в список
            names.add(child.getAttribute("name", null));
        }
	    // вернуть список имен
        return names.toArray(new String[names.size()]); 
	}
	///////////////////////////////////////////////////////////////////////
	// Управление физическими потоками
	///////////////////////////////////////////////////////////////////////
    @Override protected ContainerStream createStream(Object name) throws IOException
    {
        // проверить поддержку операции
        if (document == null) throw new UnsupportedOperationException(); 
        
        // получить элемент для контейнеров
        XmlKey key = document.openOrCreateKey("containers"); 
             
        // для всех контейнеров
        for (XmlKey child : key.enumerateKeys("r"))
        {
            // получить имя контейнера
            String value = child.getAttribute("name", null); 

            // сравнить имена контейнеров
            if (value.compareToIgnoreCase(name.toString()) == 0) 
            { 
                // проверить отсутствие элемента
                throw new IOException(); 
            }
        }
        // добавить новый элемент 
        XmlKey created = document.createKey("container"); 
            
        // указать имя контейнера
        created.setAttribute("name", name.toString()); 
            
        // вернуть поток данных в файле конфигурации
        return new ElementStream(created);
    }
    @Override protected ContainerStream openStream(Object name, String access) throws IOException
    {
        // проверить поддержку операции
        if (document == null) throw new UnsupportedOperationException(); 
        
        // получить элемент для контейнеров
        XmlKey key = document.openKey("containers", access); 

        // проверить наличие элемента
        if (key == null) throw new NoSuchElementException(); 

        // для всех контейнеров
        for (XmlKey child : key.enumerateKeys(access))
        {
            // получить имя контейнера
            String value = child.getAttribute("name", null); 

            // сравнить имена контейнеров
            if (value.compareToIgnoreCase(name.toString()) == 0) 
            { 
                // вернуть поток данных в файле конфигурации
                return new ElementStream(child); 
            }
        }
        // выбросить исключение
        throw new NoSuchElementException(); 
    }
    @Override protected void deleteStream(Object name) throws IOException
    {
        // проверить поддержку операции
        if (document == null) throw new UnsupportedOperationException(); 

        // получить элемент для контейнеров
        XmlKey key = document.openKey("containers", "rw"); 
             
        // проверить наличие элемента
        if (key == null) return; 

        // для всех контейнеров
        for (XmlKey child : key.enumerateKeys("r"))
        {
            // получить имя контейнера
            String value = child.getAttribute("name", null); 

            // сравнить имена контейнеров
            if (value.compareToIgnoreCase(name.toString()) == 0) 
            { 
                // удалить контейнер
                key.deleteKey(child); return; 
            }
        }
    }
	///////////////////////////////////////////////////////////////////////////
    // Поток хранилища данных в файле конфигурации
	///////////////////////////////////////////////////////////////////////////
	private static class ElementStream extends ContainerStream
    {
	    // конструктор
	    public ElementStream(XmlKey element) 
	    
            // сохранить переданные параметры
            { this.element = element; } private final XmlKey element; 
        
        // имя контейнера
        @Override public Object name() { return uniqueID(); }
        
        // уникальный идентификатор
        @Override public String uniqueID() { return element.getAttribute("name", null); }
        
        // прочитать данные
        @Override public byte[] read() throws IOException
        {
            // получить содержимое элемента
            return Base64.getDecoder().decode(element.getValue()); 
        }
        // записать данные
		@Override public void write(byte[] buffer) throws IOException
		{
            // записать данные
            element.setValue(Base64.getEncoder().encodeToString(buffer)); 
		}
	}
}
