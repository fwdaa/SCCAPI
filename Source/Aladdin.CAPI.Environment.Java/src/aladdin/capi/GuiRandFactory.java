package aladdin.capi;
import aladdin.capi.environment.*;
import aladdin.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Фабрика создания генераторов случайных данных с использованием GUI
///////////////////////////////////////////////////////////////////////////
public class GuiRandFactory extends RefObject implements IRandFactory
{
    // класс фабрики генераторов 
    private final String className; 

    // конструктор
    public GuiRandFactory(ConfigRandFactory element)
    {
        // получить класс фабрики генераторов 
        className = element.className(); 
    }
    // создать генератор случайных данных
    @Override public IRand createRand(Object window) throws IOException
    {
        // указать загрузчик классов
        ClassLoader classLoader = ClassLoader.getSystemClassLoader(); 
        
        // загрузить фабрику генераторов 
        try (IRandFactory factory = (IRandFactory)
            Loader.loadClass(classLoader, className))
        {
            // создать генератор случайных данных
            return factory.createRand(window); 
        }
        // обработать врзможное исключение
        catch (Throwable e) { throw new IOException(e); }
    }
}
