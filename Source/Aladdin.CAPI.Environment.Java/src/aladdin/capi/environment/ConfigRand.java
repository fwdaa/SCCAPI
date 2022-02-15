package aladdin.capi.environment;
import java.io.*;
import org.w3c.dom.*;

///////////////////////////////////////////////////////////////////////////
// Элемент описания генератора случайных данных
///////////////////////////////////////////////////////////////////////////
public class ConfigRand 
{
    // имя элемента и признак обязательного использования 
    private final String name; private final String critical; 
    // имя модуля и класса фабрики
    private final String classLoader; private final String className; 
    
    // конструктор
    public ConfigRand(Element element) throws IOException
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

        // получить признак обязательного использования
        critical = element.getAttribute("critical"); 
    }
    // имя элемента
    public final String name() { return name; } 
    
    // модуль фабрики
    public final String classLoader() { return classLoader; } 
    // класс фабрики
    public final String className() { return className; } 
    
    // признак обязательного использования
    public final boolean critical() 
    { 
        // признак обязательного использования
        return (critical.length() > 0) ? Boolean.parseBoolean(critical) : false; 
    } 
}
