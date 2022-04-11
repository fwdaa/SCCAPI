package aladdin.capi.environment;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Элемент расширения
///////////////////////////////////////////////////////////////////////////
public class ConfigPlugin implements Serializable 
{
    private static final long serialVersionUID = -3801426149739278004L;
    
    // имя плагина и класса плагина
    private final String name; private final String className; 
    // размер salt-значения и число итераций
    private final int pbmSaltLength; private final int pbmIterations; 
    private final int pbeSaltLength; private final int pbeIterations;
    
    // конструктор
    public ConfigPlugin(String name, String className, 
        int pbmSaltLength, int pbmIterations, int pbeSaltLength, int pbeIterations)
    {
        // сохранить переданные параметры
        this.name = name; this.className = className; 
        
        // сохранить переданные параметры
        this.pbmSaltLength = pbmSaltLength; this.pbmIterations = pbmIterations; 
        this.pbeSaltLength = pbeSaltLength; this.pbeIterations = pbeIterations; 
    }
    // имя плагина
    public final String name() { return name; } 
    // имя класса
    public final String className() { return className; } 
    // размер salt-значения
    public final int pbmSaltLength() { return pbmSaltLength; }
    // число итераций
    public final int pbmIterations() { return pbmIterations; }
    // размер salt-значения
    public final int pbeSaltLength() { return pbeSaltLength; }
    // число итераций
    public final int pbeIterations() { return pbeIterations; }
}
