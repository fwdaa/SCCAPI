package aladdin.io.xml;
import java.lang.reflect.*; 
import java.io.*;
import java.util.*;
import javax.xml.*;
import javax.xml.parsers.*;
import javax.xml.transform.*;
import javax.xml.transform.dom.*;
import javax.xml.transform.stream.*;
import org.w3c.dom.*;
import org.xml.sax.*;

///////////////////////////////////////////////////////////////////////////////
// Утилиты для работы с XML
///////////////////////////////////////////////////////////////////////////////
public class DOM 
{
    // создать документ
    public static Document createDocument(String rootElement) throws IOException 
    {
        // создать фабрику для DOM-провайдеров 
        DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();            
        try { 
            // создать DOM-провайдер
            DocumentBuilder docBuilder = docFactory.newDocumentBuilder(); 

            // создать новый DOM-документ
            Document document = docBuilder.newDocument(); 

            // указать самодостаточность документа
            setXmlStandalone(document, true); 

            // создать корневой элемент
            Element element = document.createElement(rootElement); 

            // добавить корневой элемент в документ
            document.appendChild(element); return document; 
        }
        // обработать возможное исключение
        catch (ParserConfigurationException e) { throw new IOException(e); }
    }
    // прочитать документ
    public static Document readDocument(String inputFile) throws IOException
    {
        // создать фабрику для DOM-провайдеров
        DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();            
        try {  
            // указать параметры фабрики
            setFeature(docFactory, XMLConstants.FEATURE_SECURE_PROCESSING, true); 
            
            // создать DOM-провайдер
            DocumentBuilder docBuilder = docFactory.newDocumentBuilder(); 

            // прочитать DOM-документ 
            Document document = docBuilder.parse(new File(inputFile)); 

            // выполнить нормализацию
            document.getDocumentElement().normalize(); return document; 
        }
        // обработать возможное исключение
        catch (SAXException                 e) { throw new IOException(e); }
        catch (ParserConfigurationException e) { throw new IOException(e); }
    }
    // прочитать дочерние элементы 
    public static Element[] readElements(Node node)
    {
        // создать список элементов
        List<Element> elements = new ArrayList<Element>(); 
        
        // получить дочерние элементы 
        NodeList nodes = node.getChildNodes(); 
            
        // для всех элементов
        for (int i = 0; i < nodes.getLength(); i++) 
        {
            // проверить тип элемента
            if (nodes.item(i).getNodeType() != Node.ELEMENT_NODE) continue;                
                
            // добавить элемент в список
            elements.add((Element)nodes.item(i));
        }
        // вернуть список элементов
        return elements.toArray(new Element[elements.size()]); 
    }
    // записать документ
    public static void writeDocument(Document document, String outputFile) throws IOException
    {
        // создать фабрику для провайдеров сохранения DOM-документов
        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        try { 
            // создать провайдер сохранения DOM-документов
            Transformer transformer = transformerFactory.newTransformer();

            // указать наличие форматирования при сохранении
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");            

            // указать сохранение всего документа
            Source source = new DOMSource(document);

            // открыть файл для сохранения 
            try (OutputStream stream = new FileOutputStream(outputFile))
            {
                // указать файл для результата
                Result result = new StreamResult(stream);

                // выполнить преобразование
                transformer.transform(source, result); stream.flush(); 
            }
        }
        // обработать возможное исключение
        catch (TransformerException e) { throw new IOException(e); }
    }
    // установить параметры фабрики для DOM-провайдеров
    private static void setFeature(DocumentBuilderFactory docFactory, 
        String property, boolean value) throws ParserConfigurationException
    {
        try { 
            // указать класс фабрики
            Class<?> docFactoryClass = docFactory.getClass(); 
            
            // проверить наличие метода
            Method method = docFactoryClass.getDeclaredMethod(
                "setFeature", String.class, boolean.class
            ); 
            // вызвать метод
            method.invoke(docFactory, property, value); 
        }
        // обработать отсутствие метода
        catch (NoSuchMethodException e) {} 
        
        // при возникновении ошибки
        catch (InvocationTargetException e) 
        { 
            // получить внутреннее исключение
            Throwable exception = e.getTargetException(); 
                    
            // при совместимости типов 
            if (exception instanceof ParserConfigurationException)
            {
                // выбросить исключение исходного типа
                throw (ParserConfigurationException)exception;
            }
            // выбросить исключение
            else throw new RuntimeException(exception); 
        }
        // обработать неожидаемое исключение
        catch (IllegalAccessException e) { throw new RuntimeException(e); }
    }
    private static void setXmlStandalone(
        Document document, boolean value) throws DOMException
    {
        try { 
            // указать класс фабрики
            Class<?> documentClass = document.getClass(); 
            
            // проверить наличие метода
            Method method = documentClass.getDeclaredMethod(
                "setXmlStandalone", boolean.class
            ); 
            // вызвать метод
            method.invoke(document, value); 
        }
        // обработать отсутствие метода
        catch (NoSuchMethodException e) {} 
            
        // при возникновении ошибки
        catch (InvocationTargetException e) 
        { 
            // получить внутреннее исключение
            Throwable exception = e.getTargetException(); 
                    
            // при совместимости типов 
            if (exception instanceof DOMException)
            {
                // выбросить исключение исходного типа
                throw (DOMException)exception;
            }
            // выбросить исключение
            else throw new RuntimeException(exception); 
        }
        // обработать неожидаемое исключение
        catch (IllegalAccessException e) { throw new RuntimeException(e); }
    }
}
