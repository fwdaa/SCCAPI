package aladdin.io.xml;
import java.io.*; 
import java.util.*; 
import javax.xml.parsers.*;
import javax.xml.transform.*;
import javax.xml.transform.dom.*;
import javax.xml.transform.stream.*;
import org.w3c.dom.*;
import org.xml.sax.*;

///////////////////////////////////////////////////////////////////////////
// Иерархическая структура XML
///////////////////////////////////////////////////////////////////////////
public final class XmlKey
{
    // способ сохранения документа
    public static interface Save
    {
        // сохранить документ
        void invoke(Document document) throws IOException; 
    }; 
    // создать документ
    public static XmlKey createDocument(String fileName, String root) throws IOException
    {
        // создать фабрику для провайдеров сохранения DOM-документов
        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        try {
            // создать провайдер сохранения DOM-документов
            Transformer transformer = transformerFactory.newTransformer();
            
            // указать наличие отступов
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");            
            
            // создать документ
            return createDocument(fileName, root, transformer); 
        }
        // обработать возможное исключение
        catch (TransformerException e) { throw new IOException(e); }
    }
    // создать документ
    public static XmlKey createDocument(
        String fileName, String root, Transformer transformer) throws IOException
    { 
        // проверить наличие параметров
        if (transformer == null) throw new IllegalArgumentException(); 
        
        // проверить отсутствие файла
        File file = new File(fileName); if (file.exists()) throw new IOException(); 
                
        // указать функцию сохранения документа
        XmlKey.Save save = new XmlKey.Save() 
        {
            // сохранить документ
            @Override public void invoke(Document document) throws IOException
            {
                // указать сохранение всего документа
                Source source = new DOMSource(document);

                // открыть файл для сохранения 
                try (OutputStream stream = new FileOutputStream(fileName))
                {
                    // указать файл для результата
                    Result result = new StreamResult(stream);

                    // выполнить преобразование
                    transformer.transform(source, result); stream.flush(); 
                }
                // обработать возможное исключение
                catch (TransformerException e) { throw new IOException(e); }
            }
        }; 
        // создать фабрику для DOM-провайдеров
        DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();            
        try {
            // создать DOM-провайдер
            DocumentBuilder docBuilder = docFactory.newDocumentBuilder(); 

            // создать новый DOM-документ
            Document document = docBuilder.newDocument(); 

            // создать корневой элемент
            Element element = document.createElement("configuration"); 

            // добавить корневой элемент в документ
            document.appendChild(element); save.invoke(document);

            // вернуть документ
            return new XmlKey(document, save); 
        }
        // обработать возможное исключение
        catch (ParserConfigurationException e) { throw new IOException(e); }
    }
    // открыть документ
    public static XmlKey openDocument(String fileName, String access) throws IOException
    {
        // указать отсутствие записи
        Transformer transformer = null; if (!access.equals("r"))
        {
            // создать фабрику для провайдеров сохранения DOM-документов
            TransformerFactory transformerFactory = TransformerFactory.newInstance();
            try {
                // создать провайдер сохранения DOM-документов
                transformer = transformerFactory.newTransformer();

                // указать наличие отступов
                transformer.setOutputProperty(OutputKeys.INDENT, "yes");            
            }
            // обработать возможное исключение
            catch (TransformerException e) { throw new IOException(e); }
        }
        // открыть документ  
        return openDocument(fileName, transformer); 
    }; 
    // открыть документ
    public static XmlKey openDocument(String fileName, Transformer transformer) throws IOException
    { 
        // проверить наличие файла
        File file = new File(fileName); if (!file.exists()) throw new IOException(); 
                
        // указать функцию сохранения документа
        XmlKey.Save save = (transformer == null) ? null : new XmlKey.Save() 
        {
            // сохранить документ
            @Override public void invoke(Document document) throws IOException
            {
                // указать сохранение всего документа
                Source source = new DOMSource(document);

                // открыть файл для сохранения 
                try (OutputStream stream = new FileOutputStream(fileName))
                {
                    // указать файл для результата
                    Result result = new StreamResult(stream);

                    // выполнить преобразование
                    transformer.transform(source, result); stream.flush(); 
                }
                // обработать возможное исключение
                catch (TransformerException e) { throw new IOException(e); }
            }
        }; 
        // создать фабрику для DOM-провайдеров
        DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();            
        try {
            // создать DOM-провайдер
            DocumentBuilder docBuilder = docFactory.newDocumentBuilder(); 

            // прочитать DOM-документ 
            Document document = docBuilder.parse(file); 

            // выполнить нормализацию
            document.getDocumentElement().normalize(); 

            // вернуть документ
            return new XmlKey(document, save); 
        }
        // обработать возможное исключение
        catch (ParserConfigurationException e) { throw new IOException(e); }
        catch (SAXException                 e) { throw new IOException(e); }
    }
    // элемент и способ сохранения документа
    private final Element element; private final Save save; 

    // конструктор
    public XmlKey(Document document, Save save) throws IOException
    { 
        // сохранить переданные параметры
        this.element = document.getDocumentElement(); this.save = save; 

        // проверить наличие корневого элемента
        if (this.element == null) throw new IOException(); 
    } 
    // конструктор
    public XmlKey(Element element, Save save)
    { 
        // сохранить переданные параметры
        this.element = element; this.save = save; 
    } 
    ///////////////////////////////////////////////////////////////////////
    // Перечислить элементы
    ///////////////////////////////////////////////////////////////////////
	public List<XmlKey> enumerateKeys(String access)
    {
        // проверить соответствие доступа
        if (save == null && !access.equals("r"))
        {
            // выбросить исключение
            throw new SecurityException(); 
        }
        // создать список разделов
        List<XmlKey> childs = new ArrayList<XmlKey>(); 
        
        // получить список дочерних элементов
        NodeList list = element.getChildNodes(); 

        // для всех дочерних элементов
        for (int i = 0; i < list.getLength(); i++)
        {
            // получить элемент
            Node node = list.item(i); 
            
            // проверить тип элемента
            if (node.getNodeType() != Node.ELEMENT_NODE) continue; 

            // добавить дочерний элемент
            childs.add(new XmlKey((Element)node, 
                !access.equals("r") ? save : null
            )); 
        }
        return childs; 
    }
    ///////////////////////////////////////////////////////////////////////
    // Создать новый элемент
    ///////////////////////////////////////////////////////////////////////
	public XmlKey createKey(String name) throws IOException
    {
        // проверить соответствие доступа
        if (save == null) throw new SecurityException(); 

        // указать используемый документ
        Document document = element.getOwnerDocument(); 

        // создать элемент
        Element created = document.createElement(name); 

        // добавить элемент в документ
        element.appendChild(created); save.invoke(document); 
            
        // вернуть созданный элемент
        return new XmlKey(created, save); 
    } 
    ///////////////////////////////////////////////////////////////////////
    // Открыть или создать раздел
    ///////////////////////////////////////////////////////////////////////
	public XmlKey openOrCreateKey(String name) throws IOException
    {
        // проверить соответствие доступа
        if (save == null) throw new SecurityException(); 

        // получить список дочерних элементов
        NodeList list = element.getChildNodes(); 

        // для всех дочерних элементов
        for (int i = 0; i < list.getLength(); i++)
        {
            // получить элемент
            Node node = list.item(i); 
            
            // проверить тип элемента
            if (node.getNodeType() != Node.ELEMENT_NODE) continue; 

            // проверить имя элемента
            if (!node.getNodeName().equals(name)) continue; 

            // вернуть дочерний элемент
            return new XmlKey((Element)node, save); 
        }
        // создать новый элемент
        return createKey(name); 
    } 
	///////////////////////////////////////////////////////////////////////
	// Открыть элемент
	///////////////////////////////////////////////////////////////////////
	public XmlKey openKey(String name, String access)
    {
        // проверить соответствие доступа
        if (save == null && !access.equals("r"))
        {
            // выбросить исключение
            throw new SecurityException(); 
        }
        // получить список дочерних элементов
        NodeList list = element.getChildNodes(); 
        
        // для всех дочерних элементов
        for (int i = 0; i < list.getLength(); i++)
        {
            // получить элемент
            Node node = list.item(i); 
            
            // проверить тип элемента
            if (node.getNodeType() != Node.ELEMENT_NODE) continue; 

            // проверить имя элемента
            if (!node.getNodeName().equals(name)) continue; 

            // вернуть дочерний элемент
            return new XmlKey((Element)node, 
                !access.equals("r") ? save : null
            ); 
        }
        return null; 
    } 
    ///////////////////////////////////////////////////////////////////////
    // Удалить элемент
    ///////////////////////////////////////////////////////////////////////
	public void deleteKey(XmlKey key) throws IOException
    {
        // проверить соответствие элементов
        if (key.element.getParentNode() != element)        
        {
            // выбросить исключение
            throw new IllegalStateException(); 
        }
        // проверить соответствие доступа
        if (save == null) throw new SecurityException(); 

        // получить документ элемента
        Document document = element.getOwnerDocument(); 

        // удалить подраздел
        element.removeChild(key.element); save.invoke(document); 
    }
	///////////////////////////////////////////////////////////////////////
    // Получить значение элемента
	///////////////////////////////////////////////////////////////////////
	public String getValue() 
    { 
        // вернуть содержимое элемента
        return (!element.hasChildNodes()) ? element.getNodeValue() : null;
    }
	///////////////////////////////////////////////////////////////////////
    // Установить значение элемента
	///////////////////////////////////////////////////////////////////////
	public void setValue(String value) 
    { 
        // проверить корректность операции
        if (element.hasChildNodes()) throw new IllegalStateException();

        // проверить соответствие доступа
        if (save == null) throw new SecurityException(); 

        // установить значение элемента
        element.setNodeValue((value != null) ? value : new String()); 
    }
	///////////////////////////////////////////////////////////////////////
    // Перечислить атрибуты
	///////////////////////////////////////////////////////////////////////
	public String[] enumerateAttributes()
    {
        // создать список имен
        List<String> names = new ArrayList<String>(); 
        
        // получить атрибуты
        NamedNodeMap attributes = element.getAttributes(); 

        // для всех атрибутов элемента
        for (int i = 0; i < attributes.getLength(); i++)
        {
            // получить атрибут
            Attr attribute = (Attr)attributes.item(i); 
            
            // добавить имя атрибута
            names.add(attribute.getName()); 
        }
        // вернуть список имен
        return names.toArray(new String[names.size()]); 
    }
	///////////////////////////////////////////////////////////////////////
    // Получить значение атрибута
	///////////////////////////////////////////////////////////////////////
	public String getAttribute(String name, String def)
    {
        // получить атрибуты
        NamedNodeMap attributes = element.getAttributes(); 

        // для всех атрибутов элемента
        for (int i = 0; i < attributes.getLength(); i++)
        {
            // получить атрибут
            Attr attribute = (Attr)attributes.item(i); 
            
            // проверить совпадение имени
            if (!attribute.getName().equals(name)) continue; 

            // вернуть значение атрибута
            return attribute.getValue(); 
        }
        return def; 
    }
	///////////////////////////////////////////////////////////////////////
    // Установить значение атрибута
	///////////////////////////////////////////////////////////////////////
	public void setAttribute(String name, String value) throws IOException
    {
        // проверить соответствие доступа
        if (save == null) throw new SecurityException(); 

        // проверить наличие значения 
        if (value == null) value = new String(); 

        // получить документ элемента
        Document document = element.getOwnerDocument(); 

        // указать значение атрибута
        element.setAttribute(name, value); save.invoke(document); 
    }
    ///////////////////////////////////////////////////////////////////////
    // Удалить атрибут
    ///////////////////////////////////////////////////////////////////////
	public void deleteAttribute(String name) throws IOException
    {
        // проверить соответствие доступа
        if (save == null) throw new SecurityException(); 

        // получить документ элемента
        Document document = element.getOwnerDocument(); 

        // получить атрибуты
        NamedNodeMap attributes = element.getAttributes(); 

        // для всех атрибутов элемента
        for (int i = 0; i < attributes.getLength(); i++)
        {
            // получить атрибут
            Attr attribute = (Attr)attributes.item(i); 
            
            // проверить совпадение имени
            if (!attribute.getName().equals(name)) continue; 

            // удалить атрибут
            element.removeAttributeNode(attribute); save.invoke(document); return; 
        }
    }
}
