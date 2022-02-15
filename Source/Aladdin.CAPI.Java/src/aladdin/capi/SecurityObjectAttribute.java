package aladdin.capi;
import java.lang.reflect.*; 
import java.lang.annotation.*; 
import java.util.*; 

///////////////////////////////////////////////////////////////////////////
// Атрибут необходимости аутентификации при вызове метода
///////////////////////////////////////////////////////////////////////////
public class SecurityObjectAttribute implements Annotation
{
    // конструктор
    public SecurityObjectAttribute(String name) { this.name = name; } private final String name; 

    // тип атрибута
    @Override public Class<? extends Annotation> annotationType() { return getClass(); }
    
    // защищаемый объект
    public SecurityObject getObject(Object reference) throws Throwable
    {
        // определить класс объекта
        Class<?> classType = reference.getClass(); 
        do {
            try { 
                // получить описание поля
                Field fieldInfo = classType.getField(name); 

                // получить значение поля
                return (SecurityObject)fieldInfo.get(reference); 
            }
            // обработать возможную ошибку
            catch (NoSuchFieldException e) {}
            try { 
                // получить описание метода
                Method methodInfo = classType.getMethod(name); 

                // получить значение метода
                return (SecurityObject)methodInfo.invoke(reference); 
            }
            // обработать возможную ошибку
            catch (InvocationTargetException e) { throw e.getTargetException(); }
            catch (NoSuchMethodException     e) {}
            catch (SecurityException         e) {}
            
            // перейти на базовый класс
            classType = classType.getSuperclass(); 
        }
        // при ошибке выбросить исключение
        while (classType != null); throw new NoSuchElementException(); 
    }
}
