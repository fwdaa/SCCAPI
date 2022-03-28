package aladdin;
import java.io.*;
import java.lang.reflect.*;
import java.net.*;

///////////////////////////////////////////////////////////////////////////////
// Загрузка классов
///////////////////////////////////////////////////////////////////////////////
public class Loader 
{
	// загрузить объект
    @SuppressWarnings({"deprecation"}) 
	public static Object loadClass(
        String classPath, String className, Object... args) throws Throwable
    {
        // получить имя файла 
        File fileName = new File(classPath); URL url = null; 
        try { 
            // получить метод класса
            Method method = fileName.getClass().getMethod("toURI"); 
            
            // выполнить метод класса
            Object uri = method.invoke(fileName); 
            
            // получить метод класса
            method = uri.getClass().getMethod("toURL"); 

            // выполнить метод класса
            url = (URL)method.invoke(uri); 
        }
        // обработать возможное исключение
        catch (NoSuchMethodException e) { url = fileName.toURL(); }
        
        // создать загрузчик типов
        ClassLoader loader = new URLClassLoader(
            new URL[] { url }, Loader.class.getClassLoader()
        );        
        // загрузить класс
        return loadClass(loader, className, args); 
	}
	// загрузить объект
    @SuppressWarnings({"rawtypes"}) 
	public static Object loadClass(
        ClassLoader loader, String className, Object... args) throws Throwable
    {
		// получить описание типа
		Class<?> type = loader.loadClass(className); 

        // создать список типов аргументов
        Class[] argTypes = new Class[args.length]; 

        // заполнить список типов аргументов
        for (int i = 0; i < args.length; i++) argTypes[i] = args[i].getClass(); 

        // получить описание конструктора
		Constructor constructor = type.getConstructor(argTypes); 
        
		// загрузить объект
		try { return constructor.newInstance(args); }

        // обработать исключение
        catch (InvocationTargetException e) { throw e.getTargetException(); }
	}
}
