package aladdin.capi.environment;
import java.io.*; 
import org.w3c.dom.*;

///////////////////////////////////////////////////////////////////////////
// Элемент описания идентификатора ключа
///////////////////////////////////////////////////////////////////////////
public class ConfigKey 
{
    // идентификатор ключа, отображаемое имя и имя расширения 
    private final String oid; private final String name; private final String plugin; 
    
    // конструктор
    public ConfigKey(Element element) throws IOException
    {
        // получить идентификатор ключа
        oid = element.getAttribute("oid"); 
        // проверить наличие идентификатора ключа
        if (oid.length() == 0) throw new IOException(); 
        
        // получить отображаемое имя
        name = element.getAttribute("name"); 
        // проверить наличие отображаемого имени
        if (name.length() == 0) throw new IOException(); 
        
        // получить имя расширения 
        plugin = element.getAttribute("plugin"); 
        // проверить наличие имени расширения 
        if (plugin.length() == 0) throw new IOException(); 
    }
    // идентификатор ключа
    public final String oid() { return oid; } 
    // отображаемое имя
    public final String name() { return name; } 
    // имя расширения 
    public String plugin() { return plugin; } 
}
