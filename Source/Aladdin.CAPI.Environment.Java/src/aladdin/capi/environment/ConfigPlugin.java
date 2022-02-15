package aladdin.capi.environment;
import java.io.*; 
import org.w3c.dom.*;

///////////////////////////////////////////////////////////////////////////
// Элемент расширения
///////////////////////////////////////////////////////////////////////////
public class ConfigPlugin 
{
    // имя плагина, имя модуля и класса плагина
    private final String name; private final String classLoader; private final String className; 
    // размер salt-значения и число итераций
    private final String pbmSaltLength; private final String pbmIterations; 
    private final String pbeSaltLength; private final String pbeIterations; 
    
    // конструктор
    public ConfigPlugin(Element element) throws IOException
    {
        // получить имя элемента 
        name = element.getAttribute("name"); 
        // проверить наличие имени элемента
        if (name.length() == 0) throw new IOException(); 
        
        // получить имя модуля
        classLoader = element.getAttribute("classLoader"); 
        // проверить наличие имени модуля
        if (classLoader.length() == 0) throw new IOException(); 
        
        // получить класс расширения
        className = element.getAttribute("className"); 
        // проверить наличие класса расширения
        if (className.length() == 0) throw new IOException(); 

        // получить размер salt-значения
        pbmSaltLength = element.getAttribute("pbmSaltLength"); 
        // проверить наличие размера 
        if (pbmSaltLength.length() == 0) throw new IOException(); 
        
        // получить число итераций
        pbmIterations = element.getAttribute("pbmIterations"); 
        // проверить наличие числа итераций
        if (pbmIterations.length() == 0) throw new IOException(); 
        
        // получить размер salt-значения
        pbeSaltLength = element.getAttribute("pbeSaltLength"); 
        // проверить наличие размера 
        if (pbeSaltLength.length() == 0) throw new IOException(); 
        
        // получить число итераций
        pbeIterations = element.getAttribute("pbeIterations"); 
        // проверить наличие числа итераций
        if (pbeIterations.length() == 0) throw new IOException(); 
    }
    // имя плагина
    public final String name() { return name; } 
    
    // имя модуля
    public final String classLoader() { return classLoader; } 
    // имя класса
    public final String className() { return className; } 
    
    // размер salt-значения
    public final int pbmSaltLength()
    { 
        // вернуть число итераций
        return Integer.parseInt(pbmSaltLength); 
    } 
    // число итераций
    public final int pbmIterations()
    { 
        // вернуть число итераций
        return Integer.parseInt(pbmIterations); 
    } 
    // размер salt-значения
    public final int pbeSaltLength()
    { 
        // вернуть число итераций
        return Integer.parseInt(pbeSaltLength); 
    } 
    // число итераций
    public final int pbeIterations()
    { 
        // вернуть число итераций
        return Integer.parseInt(pbeIterations); 
    } 
}
