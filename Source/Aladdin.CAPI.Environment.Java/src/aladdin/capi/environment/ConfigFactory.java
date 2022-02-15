package aladdin.capi.environment;
import java.io.*;
import org.w3c.dom.*;

///////////////////////////////////////////////////////////////////////////
// Элемент описания фабрики классов
///////////////////////////////////////////////////////////////////////////
public class ConfigFactory 
{
    // имя фабрики, имя модуля и класса фабрики
    private final String name; private final String classLoader; private final String className; 
    
    // конструктор
    public ConfigFactory(Element element) throws IOException
    {
        // получить имя элемента 
        name = element.getAttribute("name"); 
        // проверить наличие имени элемента
        if (name.length() == 0) throw new IOException(); 
        
        // получить имя модуля
        classLoader = element.getAttribute("classLoader"); 
        // проверить наличие имени модуля
        if (classLoader.length() == 0) throw new IOException(); 
        
        // получить класс фабрики
        className = element.getAttribute("className"); 
        // проверить наличие класса фабрики
        if (className.length() == 0) throw new IOException(); 
    }
    // имя элемента
    public final String name() { return name; }
    
    // модуль фабрики
    public final String classLoader() { return classLoader; } 
    // класс фабрики
    public final String className() { return className; } 
}
