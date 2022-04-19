package aladdin.capi;
import aladdin.capi.pbe.*; 
import aladdin.capi.environment.*; 
import aladdin.*; 
import java.io.*;
import java.lang.reflect.*;

///////////////////////////////////////////////////////////////////////////
// Элемент расширения с использованием GUI
///////////////////////////////////////////////////////////////////////////
public class GuiPlugin extends RefObject implements ICulturePlugin
{
    // класс плагина
    private final String className; 
    // параметры шифрования по паролю
    private final PBEParameters pbeParameters; 

    // конструктор
    public GuiPlugin(ConfigPlugin element) 
    {
        // получить класс расширения
        className = element.className(); 
        
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
        // проверить наличие имени класса
        if (className == null || className.length() == 0) 
        {
            // при ошибке выбросить исключение
            throw new UnsupportedOperationException(); 
        }
        // указать загрузчик классов
        ClassLoader classLoader = ClassLoader.getSystemClassLoader(); 
        try { 
            // загрузить класс
            Class<?> type = classLoader.loadClass(className); 

            // получить описание конструктора
            Constructor<?> constructor = type.getConstructor(); 
            
            // загрузить плагин
            try (ICulturePlugin plugin = (ICulturePlugin)constructor.newInstance())
            {
                // получить параметры ключа
                return plugin.getParameters(rand, keyOID, keyUsage); 
            }
        }
        // обработать врзможное исключение
        catch (InvocationTargetException e) { throw new IOException(e.getMessage()); }
        catch (Throwable                 e) { throw new IOException(e             ); }
    }
    // параметры шифрования по паролю
    @Override public PBECulture getPBECulture(
        Object window, String keyOID) throws IOException
    {
        // проверить наличие имени класса
        if (className == null || className.length() == 0) 
        {
            // при ошибке выбросить исключение
            throw new UnsupportedOperationException(); 
        }
        // указать загрузчик классов
        ClassLoader classLoader = ClassLoader.getSystemClassLoader(); 
        try { 
            // загрузить класс
            Class<?> type = classLoader.loadClass(className); 

            // получить описание конструктора
            Constructor<?> constructor = type.getConstructor(); 
            
            // загрузить плагин
            try (ICulturePlugin plugin = (ICulturePlugin)constructor.newInstance())
            {
                // получить параметры шифрования по паролю
                return plugin.getPBECulture(window, keyOID); 
            }
        }
        // обработать врзможное исключение
        catch (InvocationTargetException e) { throw new IOException(e.getMessage()); }
        catch (Throwable                 e) { throw new IOException(e             ); }
    }
}
