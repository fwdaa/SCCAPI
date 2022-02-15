package aladdin.asn1;
import java.lang.reflect.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Фабрика создания объекта для конкретного типа
///////////////////////////////////////////////////////////////////////////
public class ObjectFactory<T extends IEncodable> implements IObjectFactory<T>
{
    // тип объекта
    private final Class<? extends T> type; 
    
    // метод проверки корректности типа 
    private final Method methodValidTag; 
    
    // метод проверки корректности объекта
    private final Method methodValidate; private final Object[] args; 
        
    // конструктор
    public ObjectFactory(Class<? extends T> type, Object... args) throws NoSuchMethodException
    { 
        // сохранить переданные параметры
        this.type = type; this.args = args; 

        // указать типы аргументов
        Class<?>[] types = new Class<?>[] { Tag.class };   
            
        // указать метод проверки корректности типа 
        methodValidTag = type.getMethod("isValidTag", types); 
        
        // при указании аргументов
        if (args.length == 0) { methodValidate = null; }
        else { 
            // выделить память для типов аргументов
            types = new Class<?>[args.length + 2]; 

            // указать типы аргументов
            types[0] = type; types[1] = boolean.class;
        
            // указать типы аргументов
            for (int i = 0; i < args.length; i++) types[i + 2] = args[i].getClass(); 
                
            // найти соответствующий метод
            methodValidate = type.getMethod("validate", types);
        } 
    }
    // проверить допустимость типа
    @Override public final boolean isValidTag(Tag x)
    {
        try { 
            // проверить допустимость типа
            Object object = methodValidTag.invoke(null, x); 

            // выполнить преобразование типа
            return (boolean)object; 
        }
        // обработать возможное исключение
        catch (Throwable e) { return false; }
    }
    // раскодировать объект
    @SuppressWarnings({"unchecked"}) 
    @Override public T decode(IEncodable encodable) throws IOException
    {
		try { 
			// найти соответствующий конструктор
			Constructor<?> constructor = type.getConstructor(IEncodable.class);

			// вызвать конструктор
			T obj = (T)constructor.newInstance(encodable);

            // проверить корректность
            validate(obj, false); return obj; 
        }
		// обработать возможные ошибки
		catch (NoSuchMethodException     e) { throw new RuntimeException(e); }
		catch (InstantiationException    e) { throw new RuntimeException(e); }
		catch (IllegalAccessException    e) { throw new RuntimeException(e); }
        catch (InvocationTargetException e) 
        { 
            // проверить тип исключения
            if (e.getCause() instanceof IOException) throw (IOException)e.getCause(); 
            
            // выбросить исключение
            throw new RuntimeException(e);
        }
    }
    // проверить корректность объекта
    @Override public void validate(IEncodable encodable, boolean encode) throws IOException
    { 
		// проверить корректность объекта
		if (!type.isAssignableFrom(encodable.getClass())) 
        {
            // ошибка - некорректный объект
            if (encode) throw new IllegalArgumentException(); else throw new IOException();
        }
        // проверить необходимость действий
        if (methodValidate == null) return; 
                        
        // указать аргументы
        Object[] parameters = aladdin.util.Array.concat(new Object[] { encodable, encode }, args); 
                    
        // проверить допустимость типа
        try { methodValidate.invoke(null, parameters); } 
                            
        // обработать возможные ошибки
        catch (IllegalAccessException    e) { throw new RuntimeException(e); }
        catch (InvocationTargetException e) 
        { 
            // проверить тип исключения
            if (e.getCause() instanceof IOException) throw (IOException)e.getCause(); 
            
            // выбросить исключение
            throw new RuntimeException(e);
        }        
    }
}