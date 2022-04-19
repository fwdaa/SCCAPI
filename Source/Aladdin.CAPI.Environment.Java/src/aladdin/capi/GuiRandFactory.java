package aladdin.capi;
import aladdin.capi.environment.*;
import aladdin.*; 
import java.io.*; 
import java.lang.reflect.*;

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
        try {
            // загрузить класс
            Class<?> type = classLoader.loadClass(className); 

            // получить описание конструктора
            Constructor<?> constructor = type.getConstructor(); 

            // загрузить фабрику генераторов 
            try (IRandFactory factory = (IRandFactory)constructor.newInstance())
            {
                // создать генератор случайных данных
                return factory.createRand(window); 
            }
        }
        // обработать врзможное исключение
        catch (InvocationTargetException e) { throw new IOException(e.getMessage()); }
        catch (Throwable                 e) { throw new IOException(e             ); }
    }
}
