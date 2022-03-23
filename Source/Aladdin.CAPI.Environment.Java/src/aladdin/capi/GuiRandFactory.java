package aladdin.capi;
import aladdin.capi.environment.*;
import aladdin.*; 
import java.io.*; 
import java.net.*;
import java.lang.reflect.*;

///////////////////////////////////////////////////////////////////////////
// Фабрика создания генераторов случайных данных с использованием GUI
///////////////////////////////////////////////////////////////////////////
public class GuiRandFactory extends RefObject implements IRandFactory
{
    // класса фабрики генераторов 
    private final String classLoader; private final String className; 

    // конструктор
    public GuiRandFactory(ConfigRandFactory element)
    {
        // получить класс фабрики генераторов 
        classLoader = element.classLoader(); className = element.className(); 
    }
    // создать генератор случайных данных
    @Override public IRand createRand(Object window) throws IOException
    {
        // загрузить фабрику генераторов 
        try (IRandFactory factory = loadFactory(className))
        {
            // создать генератор случайных данных
            return factory.createRand(window); 
        }
        // обработать врзможное исключение
        catch (Throwable e) { throw new IOException(e); }
    }
	// загрузить фабрику генераторов 
	private IRandFactory loadFactory(String className) throws Throwable
	{
        // получить имя файла 
        File fileName = new File(classLoader); URL url = fileName.toURI().toURL(); 
        
        // создать загрузчик типов
        ClassLoader loader = new URLClassLoader(
            new URL[] { url }, getClass().getClassLoader()
        );        
		// получить описание типа
		Class<?> type = loader.loadClass(className); 

        // получить описание конструктора
		Constructor constructor = type.getConstructor(); 
        
		// загрузить объект
		try { return (IRandFactory)constructor.newInstance(); }

        // обработать исключение
        catch (InvocationTargetException e) { throw e.getTargetException(); }
	}
    
}
