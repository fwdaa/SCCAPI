package aladdin.asn1;
import java.lang.reflect.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Фабрика создания объектов SEQUENCE
///////////////////////////////////////////////////////////////////////////
public class SequenceFactory<T extends IEncodable> extends ObjectFactory<IEncodable>
{
    // тип элемента последовательности
    private final Class<? extends T> type; 
    
    // конструктор
    public SequenceFactory(Class<? extends T> type, Object... args) throws NoSuchMethodException
    { 
        // сохранить переданные параметры
        super(Sequence.class, args); this.type = type; 
    }
    // раскодировать объект
    @SuppressWarnings({"unchecked"}) 
    @Override public Sequence<T> decode(IEncodable encodable) throws IOException
    {
		try { 
			// найти соответствующий конструктор
			Constructor<?> constructor = type.getConstructor(Class.class, IEncodable.class);

			// вызвать конструктор
			Sequence<T> obj = (Sequence<T>)constructor.newInstance(type, encodable);

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
}
