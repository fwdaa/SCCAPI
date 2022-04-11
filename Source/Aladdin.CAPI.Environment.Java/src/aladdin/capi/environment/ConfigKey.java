package aladdin.capi.environment;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Элемент описания идентификатора ключа
///////////////////////////////////////////////////////////////////////////
public class ConfigKey implements Serializable
{
    private static final long serialVersionUID = 3054550240494822911L;
    
    // идентификатор ключа, отображаемое имя
    private final String oid; private final String name; 
    // имя расширения и класс культуры 
    private final String plugin; private final String className; 
    
    // конструктор
    public ConfigKey(String oid, String name, String plugin, String className)
    {
        // сохранить переданные параметры
        this.oid = oid; this.name = name; this.plugin = plugin; this.className = className;
    }
    // идентификатор ключа
    public final String oid() { return oid; } 
    // отображаемое имя
    public final String name() { return name; } 
    // имя расширения 
    public String plugin() { return plugin; } 
    // имя класса
    public final String className() { return className; } 
}
