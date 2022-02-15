package aladdin.capi.software;
import aladdin.*;
import aladdin.capi.*; 
import aladdin.io.xml.*; 
import java.io.*;
import java.util.*; 
import org.w3c.dom.*;

///////////////////////////////////////////////////////////////////////////
// Раздел файла конфигурации как хранилище программных контейнеров
///////////////////////////////////////////////////////////////////////////
public class ConfigStore extends ContainerStore
{
	// имя файла конфигурации и модель документа
	private final String configFile; private Document document; 

	// конструктор
	public ConfigStore(CryptoProvider provider, Scope scope, String configName) 
    {
        // сохранить переданные параметры
        super(provider, scope); document = null; 
        
        // получить профиль пользователя
        String directory = scope.equals(Scope.SYSTEM) ? 
            OS.INSTANCE.getSharedFolder() : OS.INSTANCE.getUserFolder(); 

        // указать полный путь к файлу
        configFile = String.format("%1$s%2$s%3$s", directory, File.separator, configName); 
        try {
            // при наличии файла
            File file = new File(configFile); if (file.exists())
            {
                // прочитать модель документа
                document =  DOM.readDocument(configFile); 
            }
            // при отсутствии файла создать пустой документ
            else document = DOM.createDocument("configuration"); 
        }
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
        
        // получить элемент для контейнеров
        NodeList containersNodes = document.getElementsByTagName("containers");
            
        // проверить наличие элемента
        if (containersNodes.getLength() == 0) return new String[0]; 
        
        // создать список имен
        List<String> names = new ArrayList<String>(); 
        
        // для всех контейнеров
        for (Element element : DOM.readElements(containersNodes.item(0))) 
        {
            // получить имя контейнера
            String name = element.getAttribute("name"); 
            
            // добавить имя контейнера в список
            if (name.length() != 0) names.add(name);
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
        NodeList containersNodes = document.getElementsByTagName("containers"); 
            
        // при отсутствии элемента
        Element containersNode = null; if (containersNodes.getLength() == 0)
        {
            // создать новый элемент
            containersNode = document.createElement("containers"); 
            
            // добавить элемент в документ
            document.getDocumentElement().appendChild(containersNode); 
        }
        // сохранить элемент для контейнеров
        else { containersNode = (Element)containersNodes.item(0); }
        
        // для всех контейнеров
        for (Element element : DOM.readElements(containersNode)) 
        {
            // сравнить имена контейнеров
            if (element.getAttribute("name").equalsIgnoreCase((String)name)) 
            { 
                // проверить отсутствие элемента
                throw new IOException(); 
            }
        }
        // создать новый элемент
        Element containerNode = document.createElement("container"); 

        // добавить элемент в документ
        containersNode.appendChild(containerNode); 

        // указать имя элемента 
        containerNode.setAttribute("name", (String)name); 

        // вернуть поток данных в файле конфигурации
        return new ReadWriteElementStream(configFile, document, containerNode); 
    }
    @Override protected ContainerStream openStream(Object name, String access) throws IOException
    {
        // проверить поддержку операции
        if (document == null) throw new UnsupportedOperationException(); 
        
        // получить элемент для контейнеров
        NodeList containersNodes = document.getElementsByTagName("containers"); 
            
        // проверить наличие элемента
        if (containersNodes.getLength() == 0) throw new NoSuchElementException(); 

        // получить элемент для контейнеров
        Element containersNode = (Element)containersNodes.item(0);
        
        // для всех контейнеров
        for (Element element : DOM.readElements(containersNode)) 
        {
            // сравнить имена контейнеров
            if (element.getAttribute("name").equalsIgnoreCase((String)name)) 
            { 
                // вернуть поток данных в файле конфигурации
                if (!access.equals("rw")) return new ReadElementStream(element); 

                // вернуть поток данных в файле конфигурации
                else return new ReadWriteElementStream(configFile, document, element); 
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
        NodeList containersNodes = document.getElementsByTagName("containers"); 
            
        // проверить наличие элемента
        if (containersNodes.getLength() == 0) return; 

        // получить элемент для контейнеров
        Element containersNode = (Element)containersNodes.item(0);
        
        // для всех контейнеров
        for (Element element : DOM.readElements(containersNode)) 
        {
            // сравнить имена контейнеров
            if (element.getAttribute("name").equalsIgnoreCase((String)name)) 
            { 
                // удалить элемент 
                containersNode.removeChild(element); 
        
                // записать документ
                DOM.writeDocument(document, configFile); break; 
            }
        }
    }
	///////////////////////////////////////////////////////////////////////////
    // Поток хранилища данных в файле конфигурации (только для чтения)
	///////////////////////////////////////////////////////////////////////////
	private static class ReadElementStream extends ContainerStream
    {
        // узел элемента
        private final Element containerNode; 

	    // конструктор
	    public ReadElementStream(Element containerNode) throws IOException
	    {
            // сохранить переданные параметры
            this.containerNode = containerNode; 
        }
        // узел элемента
        protected final Element containerNode() { return containerNode; }
        
        // имя контейнера
        @Override public Object name() { return uniqueID(); }
        
        // уникальный идентификатор
        @Override public String uniqueID() { return containerNode.getAttribute("name"); }
        
        // прочитать данные
        @Override public byte[] read() throws IOException
        {
            // получить содержимое элемента
            String encoded = containerNode.getNodeValue(); 
            
            // раскодировать контейнер
            return Base64.getDecoder().decode(encoded); 
        }
        // записать данные
		@Override public void write(byte[] buffer) throws IOException
		{
            // выбрость исключение
            throw new IOException(); 
		}
	}
	///////////////////////////////////////////////////////////////////////////
    // Поток хранилища данных в файле конфигурации (для чтения и записи)
	///////////////////////////////////////////////////////////////////////////
	private static class ReadWriteElementStream extends ReadElementStream
    {
        // имя файла и модель документа
        private final String configFile; private final Document document; private boolean dirty;
        
	    // конструктор
	    public ReadWriteElementStream(String configFile, 
            Document document, Element containerNode) throws IOException
	    {
            // сохранить переданные параметры
            super(containerNode); this.dirty = false;
            
            // сохранить переданные параметры
            this.configFile = configFile; this.document = document; 
        }
        // освободить выделенные ресурсы
        @Override protected void onClose() throws IOException 
        {  
            // синхронизировать данные
            if (dirty) DOM.writeDocument(document, configFile);
        }
        // записать данные
		@Override public void write(byte[] buffer) throws IOException
		{
            // закодировать контейнер
            String encoded = Base64.getEncoder().encodeToString(buffer); 
            
            // записать данные
            containerNode().setNodeValue(encoded); dirty = true; 
		}
	}
}
