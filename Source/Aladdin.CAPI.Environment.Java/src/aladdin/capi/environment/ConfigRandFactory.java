package aladdin.capi.environment;
import java.io.*;
import org.w3c.dom.*;

///////////////////////////////////////////////////////////////////////////
// Элемент описания генератора случайных данных
///////////////////////////////////////////////////////////////////////////
public class ConfigRandFactory 
{
    // имя элемента и признак наличия GUI
    private final String name; private final String gui; 
    // имя модуля и класса фабрики
    private final String classLoader; private final String className; 
    
    // конструктор
    public ConfigRandFactory(Element element) throws IOException
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

        // получить признак наличия GUI
        gui = element.getAttribute("gui"); 
    }
    // имя элемента
    public final String name() { return name; } 
    
    // модуль фабрики
    public final String classLoader() { return classLoader; } 
    // класс фабрики
    public final String className() { return className; } 
    
    // признак наличия GUI
    public final boolean gui() 
    { 
        // признак наличия GUI
        return (gui.length() > 0) ? Boolean.parseBoolean(gui) : false; 
    } 
}
