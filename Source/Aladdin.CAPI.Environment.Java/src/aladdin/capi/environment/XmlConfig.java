package aladdin.capi.environment;
import java.io.*;
import java.util.*;
import javax.xml.parsers.*;
import org.w3c.dom.*;
import org.xml.sax.*;

public class XmlConfig 
{
    ///////////////////////////////////////////////////////////////////////////
    // Элемент параметров аутентификации 
    ///////////////////////////////////////////////////////////////////////////
    public static ConfigAuthentications readAuthentications(Element element) throws IOException
    {
        // получить число попыток
        String strAttempts = element.getAttribute("name"); 
        
        // выполнить преобразование типа
        int attempts = (strAttempts.length() > 0) ? Integer.parseInt(strAttempts) : 5; 
        
        // вернуть элемент описания параметров аутентификации 
        return new ConfigAuthentications(attempts); 
    }
    ///////////////////////////////////////////////////////////////////////////
    // Элемент описания фабрики классов
    ///////////////////////////////////////////////////////////////////////////
    public static ConfigFactory readFactory(Element element) throws IOException
    {
        // получить имя элемента 
        String name = element.getAttribute("name"); 
        // проверить наличие имени элемента
        if (name.length() == 0) throw new IOException(); 
        
        // получить класс фабрики
        String className = element.getAttribute("className"); 
        // проверить наличие класса фабрики
        if (className.length() == 0) throw new IOException(); 
        
        // вернуть элемент описания фабрики классов
        return new ConfigFactory(name, className); 
    }
    ///////////////////////////////////////////////////////////////////////////
    // Элемент описания генератора случайных данных
    ///////////////////////////////////////////////////////////////////////////
    public static ConfigRandFactory readRandFactory(Element element) throws IOException
    {
        // получить имя элемента 
        String name = element.getAttribute("name"); 
        // проверить наличие имени элемента
        if (name.length() == 0) throw new IOException(); 
        
        // получить класс фабрики
        String className = element.getAttribute("className"); 
        // проверить наличие класса фабрики
        if (className.length() == 0) throw new IOException(); 

        // получить признак наличия GUI
        String gui = element.getAttribute("gui"); 
        
        // вернуть элемент описания генератора случайных данных
        return new ConfigRandFactory(name, className, 
            (gui.length() > 0) ? Boolean.parseBoolean(gui) : false
        ); 
    }
    ///////////////////////////////////////////////////////////////////////////
    // Элемент расширения
    ///////////////////////////////////////////////////////////////////////////
    public static ConfigPlugin readPlugin(Element element) throws IOException
    {
        // получить имя элемента 
        String name = element.getAttribute("name"); 
        // проверить наличие имени элемента
        if (name.length() == 0) throw new IOException(); 
        
        // получить класс расширения
        String className = element.getAttribute("className"); 

        // получить размер salt-значения
        String pbmSaltLength = element.getAttribute("pbmSaltLength"); 
        // проверить наличие размера 
        if (pbmSaltLength.length() == 0) throw new IOException(); 
        
        // получить число итераций
        String pbmIterations = element.getAttribute("pbmIterations"); 
        // проверить наличие числа итераций
        if (pbmIterations.length() == 0) throw new IOException(); 
        
        // получить размер salt-значения
        String pbeSaltLength = element.getAttribute("pbeSaltLength"); 
        // проверить наличие размера 
        if (pbeSaltLength.length() == 0) throw new IOException(); 
        
        // получить число итераций
        String pbeIterations = element.getAttribute("pbeIterations"); 
        // проверить наличие числа итераций
        if (pbeIterations.length() == 0) throw new IOException(); 
        
        // вернуть элемент расширения
        return new ConfigPlugin(name, className, 
            Integer.parseInt(pbmSaltLength), Integer.parseInt(pbmIterations),
            Integer.parseInt(pbeSaltLength), Integer.parseInt(pbeIterations)
        ); 
    }
    ///////////////////////////////////////////////////////////////////////////
    // Элемент описания идентификатора ключа
    ///////////////////////////////////////////////////////////////////////////
    public static ConfigKey readKey(Element element) throws IOException
    {
        // получить идентификатор ключа
        String oid = element.getAttribute("oid"); 
        // проверить наличие идентификатора ключа
        if (oid.length() == 0) throw new IOException(); 
        
        // получить отображаемое имя
        String name = element.getAttribute("name"); 
        // проверить наличие отображаемого имени
        if (name.length() == 0) throw new IOException(); 
        
        // получить имя расширения 
        String plugin = element.getAttribute("plugin"); 
        // проверить наличие имени расширения 
        if (plugin.length() == 0) throw new IOException(); 
        
        // получить класс расширения
        String className = element.getAttribute("className"); 
        // проверить наличие класса расширения
        if (className.length() == 0) throw new IOException(); 
        
        // вернуть элемент описания идентификатора ключа
        return new ConfigKey(oid, name, plugin, className); 
    }
    ///////////////////////////////////////////////////////////////////////////
    // Параметры приложения
    ///////////////////////////////////////////////////////////////////////////
    public static ConfigSection readSection(String fileName) throws Exception
    {
        // создать фабрику для DOM-провайдеров
        DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();            
        try {  
            // создать DOM-провайдер
            DocumentBuilder docBuilder = docFactory.newDocumentBuilder(); 

            // прочитать DOM-документ 
            Document document = docBuilder.parse(new File(fileName)); 

            // выполнить нормализацию
            document.getDocumentElement().normalize(); 
            
            // прочитать параметры приложения
            return readSection(document); 
        }
        // обработать возможное исключение
        catch (SAXException                 e) { throw new IOException(e); }
        catch (ParserConfigurationException e) { throw new IOException(e); }
    }
    public static ConfigSection readSection(InputStream stream) throws Exception
    {
        // создать фабрику для DOM-провайдеров
        DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();            
        try {  
            // создать DOM-провайдер
            DocumentBuilder docBuilder = docFactory.newDocumentBuilder(); 

            // прочитать DOM-документ 
            Document document = docBuilder.parse(new InputSource(stream)); 

            // выполнить нормализацию
            document.getDocumentElement().normalize(); 
            
            // прочитать параметры приложения
            return readSection(document); 
        }
        // обработать возможное исключение
        catch (SAXException                 e) { throw new IOException(e); }
        catch (ParserConfigurationException e) { throw new IOException(e); }
    }
    // конструктор
    public static ConfigSection readSection(Document document)
    {
        // указать значение по умолчанию
        ConfigAuthentications authentications = new ConfigAuthentications(5);
        
        // создать пустые списки
        List<ConfigFactory    > factories = new ArrayList<ConfigFactory    >(); 
        List<ConfigRandFactory> rands     = new ArrayList<ConfigRandFactory>(); 
        List<ConfigPlugin     > plugins   = new ArrayList<ConfigPlugin     >(); 
        List<ConfigKey        > keys      = new ArrayList<ConfigKey        >(); 
        
        // получить элемент для параметров аутентификации
        NodeList factoriesAuthentications = document.getElementsByTagName("authentications");
            
        // проверить наличие элемента
        if (factoriesAuthentications.getLength() > 0)
        try {
            // прочитать значение элемента
            authentications = readAuthentications((Element)factoriesAuthentications.item(0)); 
        }
        catch (Throwable e) {}
        
        // получить элемент для фабрик
        NodeList factoriesNodes = document.getElementsByTagName("factories");
            
        // проверить наличие элемента
        if (factoriesNodes.getLength() > 0)
        {
            // получить дочерние элементы 
            NodeList nodes = factoriesNodes.item(0).getChildNodes(); 
            
            // для всех элементов
            for (int i = 0; i < nodes.getLength(); i++) 
            try {
                // проверить тип элемента
                if (nodes.item(i).getNodeType() != Node.ELEMENT_NODE) continue;                

                // раскодировать элемент фабрики
                factories.add(readFactory((Element)nodes.item(i)));
            }
            catch (Throwable e) {}
        }
        // получить элемент для генераторов случайных данных
        NodeList randsNodes = document.getElementsByTagName("rands");
            
        // проверить наличие элемента
        if (randsNodes.getLength() > 0)
        {
            // получить дочерние элементы 
            NodeList nodes = randsNodes.item(0).getChildNodes(); 
            
            // для всех элементов
            for (int i = 0; i < nodes.getLength(); i++) 
            try {
                // проверить тип элемента
                if (nodes.item(i).getNodeType() != Node.ELEMENT_NODE) continue;                

                // раскодировать элемент генератора случайных данных
                rands.add(readRandFactory((Element)nodes.item(i)));
            }
            catch (Throwable e) {}
        }
        // получить элемент для расширений криптографических культур
        NodeList pluginsNodes = document.getElementsByTagName("plugins");
            
        // проверить наличие элемента
        if (pluginsNodes.getLength() > 0)
        {
            // получить дочерние элементы 
            NodeList nodes = pluginsNodes.item(0).getChildNodes(); 
            
            // для всех элементов
            for (int i = 0; i < nodes.getLength(); i++) 
            try {
                // проверить тип элемента
                if (nodes.item(i).getNodeType() != Node.ELEMENT_NODE) continue;                

                // раскодировать элемент расширения криптографической культуры
                plugins.add(readPlugin((Element)nodes.item(i)));
            }
            catch (Throwable e) {}
        }
        // получить элемент для идентификаторов ключей
        NodeList keysNodes = document.getElementsByTagName("keys");
            
        // проверить наличие элемента
        if (keysNodes.getLength() > 0)
        {
            // получить дочерние элементы 
            NodeList nodes = keysNodes.item(0).getChildNodes(); 
            
            // для всех элементов
            for (int i = 0; i < nodes.getLength(); i++) 
            try {
                // проверить тип элемента
                if (nodes.item(i).getNodeType() != Node.ELEMENT_NODE) continue;                

                // раскодировать элемент идентификатора ключа
                keys.add(readKey((Element)nodes.item(i)));
            }
            catch (Throwable e) {}
        }
        // вернуть параметры
        return new ConfigSection(authentications, 
            factories.toArray(new ConfigFactory    [factories.size()]), 
            rands    .toArray(new ConfigRandFactory[rands    .size()]), 
            keys     .toArray(new ConfigKey        [keys     .size()]),
            plugins  .toArray(new ConfigPlugin     [plugins  .size()])
        ); 
    }
}
