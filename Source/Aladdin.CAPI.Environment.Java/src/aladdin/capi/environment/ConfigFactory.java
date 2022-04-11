package aladdin.capi.environment;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Элемент описания фабрики классов
///////////////////////////////////////////////////////////////////////////
public class ConfigFactory implements Serializable
{
    private static final long serialVersionUID = 8873238961263357395L;
    
    // имя фабрики и класса фабрики
    private final String name; private final String className; 
    
    // конструктор
    public ConfigFactory(String name, String className)
    {
        // сохранить переданные параметры
        this.name = name; this.className = className; 
    }
    // имя элемента
    public final String name() { return name; }
    // класс фабрики
    public final String className() { return className; } 
}
