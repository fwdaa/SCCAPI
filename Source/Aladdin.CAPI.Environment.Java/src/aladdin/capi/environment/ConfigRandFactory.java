package aladdin.capi.environment;

///////////////////////////////////////////////////////////////////////////
// Элемент описания генератора случайных данных
///////////////////////////////////////////////////////////////////////////
public class ConfigRandFactory 
{
    // имя элемента и признак наличия GUI
    private final String name; private final boolean gui; 
    // имя класса фабрики
    private final String className; 
    
    // конструктор
    public ConfigRandFactory(String name, String className, boolean gui)
    {
        // сохранить переданные параметры
        this.name = name; this.className = className; this.gui = gui;
    }
    // имя элемента
    public final String name() { return name; } 
    // класс фабрики
    public final String className() { return className; } 
    // признак наличия GUI
    public final boolean gui() { return gui; }
}
