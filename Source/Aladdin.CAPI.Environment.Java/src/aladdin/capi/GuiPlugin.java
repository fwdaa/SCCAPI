package aladdin.capi;
import aladdin.capi.pbe.*; 
import aladdin.capi.environment.*; 
import aladdin.*; 
import java.io.*;
import java.net.*;
import java.lang.reflect.*;

///////////////////////////////////////////////////////////////////////////
// Элемент расширения с использованием GUI
///////////////////////////////////////////////////////////////////////////
public class GuiPlugin extends RefObject implements ICulturePlugin
{
    // класса плагина
    private final String classLoader; private final String className; 
    // параметры шифрования по паролю
    private final PBEParameters pbeParameters; 

    // конструктор
    public GuiPlugin(ConfigPlugin element) 
    {
        // получить класс расширения
        classLoader = element.classLoader(); className = element.className(); 
        
        // создать параметры шифрования по паролю
        pbeParameters = new PBEParameters(
            element.pbmSaltLength(), element.pbmIterations(), 
            element.pbeSaltLength(), element.pbeIterations() 
        ); 
    }
    // параметры шифрования по паролю
    @Override public PBEParameters pbeParameters() { return pbeParameters; } 

    // параметры ключа
    @Override public IParameters getParameters(
        IRand rand, String keyOID, KeyUsage keyUsage) throws IOException
    {
        // загрузить плагин
        try (ICulturePlugin plugin = loadPlugin(className))
        {
            // получить параметры ключа
            return plugin.getParameters(rand, keyOID, keyUsage); 
        }
        // обработать врзможное исключение
        catch (Throwable e) { throw new IOException(e); }
    }
    // параметры шифрования по паролю
    @Override public PBECulture getCulture(
        Object window, String keyOID) throws IOException
    {
        // загрузить плагин
        try (ICulturePlugin plugin = loadPlugin(className))
        {
            // получить параметры шифрования по паролю
            return plugin.getCulture(window, keyOID); 
        }
        // обработать врзможное исключение
        catch (Throwable e) { throw new IOException(e); }
    }
	// загрузить плагин
	private ICulturePlugin loadPlugin(String className) throws Throwable
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
		Constructor constructor = type.getConstructor(
            new Class[] { pbeParameters.getClass() } 
        ); 
		// загрузить объект
		try { return (ICulturePlugin)constructor.newInstance(pbeParameters); }

        // обработать исключение
        catch (InvocationTargetException e) { throw e.getTargetException(); }
	}
}
