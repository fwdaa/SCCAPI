package aladdin.capi.environment;
import aladdin.io.xml.*;
import java.io.*;
import java.util.*; 
import javax.xml.parsers.*;
import org.w3c.dom.*;
import org.xml.sax.SAXException;

///////////////////////////////////////////////////////////////////////////
// Параметры приложения
///////////////////////////////////////////////////////////////////////////
public class ConfigSection 
{
	// фабрики алгоритмов
    private final List<ConfigFactory> factories; 
	// генераторы случайных данных
    private final List<ConfigRand> rands; 
	// расширения криптографических культур
    private final List<ConfigPlugin> plugins; 
	// идентификаторы ключей
    private final List<ConfigKey> keys; 

    // конструктор
    public static ConfigSection fromFile(String fileName) throws Exception
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
            return new ConfigSection(document); 
        }
        // обработать возможное исключение
        catch (SAXException                 e) { throw new IOException(e); }
        catch (ParserConfigurationException e) { throw new IOException(e); }
    }
    // конструктор
    public ConfigSection(Document document)
    {
        // создать пустые списки
        factories = new ArrayList<ConfigFactory>(); 
        rands     = new ArrayList<ConfigRand   >(); 
        plugins   = new ArrayList<ConfigPlugin >(); 
        keys      = new ArrayList<ConfigKey    >(); 
        
        // получить элемент для фабрик
        NodeList factoriesNodes = document.getElementsByTagName("factories");
            
        // проверить наличие элемента
        if (factoriesNodes.getLength() > 0)
        {
            // для всех фабрик
            for (Element element : DOM.readElements(factoriesNodes.item(0))) 
            try {
                // раскодировать элемент фабрики
                factories.add(new ConfigFactory(element));
            }
            catch (Throwable e) {}
        }
        // получить элемент для генераторов случайных данных
        NodeList randsNodes = document.getElementsByTagName("rands");
            
        // проверить наличие элемента
        if (randsNodes.getLength() > 0)
        {
            // для всех генераторов случайных данных
            for (Element element : DOM.readElements(randsNodes.item(0))) 
            try {
                // раскодировать элемент генератора случайных данных
                rands.add(new ConfigRand(element));
            }
            catch (Throwable e) {}
        }
        // получить элемент для расширений криптографических культур
        NodeList pluginsNodes = document.getElementsByTagName("plugins");
            
        // проверить наличие элемента
        if (pluginsNodes.getLength() > 0)
        {
            // для всех расширений криптографических культур
            for (Element element : DOM.readElements(pluginsNodes.item(0))) 
            try {
                // раскодировать элемент расширения криптографической культуры
                plugins.add(new ConfigPlugin(element));
            }
            catch (Throwable e) {}
        }
        // получить элемент для идентификаторов ключей
        NodeList keysNodes = document.getElementsByTagName("keys");
            
        // проверить наличие элемента
        if (keysNodes.getLength() > 0)
        {
            // для всех идентификаторов ключей
            for (Element element : DOM.readElements(keysNodes.item(0))) 
            try {
                // раскодировать элемент идентификатора ключа
                keys.add(new ConfigKey(element));
            }
            catch (Throwable e) {}
        }
    }
	// фабрики алгоритмов
	public final List<ConfigFactory> factories() { return factories; }
	// генераторы случайных данных
	public final List<ConfigRand> rands() { return rands; }
	// расширения криптографических культур
	public final List<ConfigPlugin> plugins() { return plugins; }
	// идентификаторы ключей
	public final List<ConfigKey> keys() { return keys; }
}
