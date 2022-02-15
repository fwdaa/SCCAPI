package aladdin.asn1;
import java.lang.reflect.*; 

///////////////////////////////////////////////////////////////////////////
// Фабрика создания фабрик альтернатив
///////////////////////////////////////////////////////////////////////////
public final class ChoiceCreator
{
    private final Class<? extends Choice> type; // тип объекта
    
    // конструктор
    public ChoiceCreator(Class<? extends Choice> type) { this.type = type; }
    
    // экземпляр фабрики
    public final Choice factory(Object... args)
    {
        // выделить память для типов аргументов
		Class<?>[] types = new Class<?>[args.length];

		// указать типы аргументов
		for (int i = 0; i < args.length; i++) types[i] = args[i].getClass();
		try { 
			// найти соответствующий конструктор
			Constructor<?> constructor = type.getConstructor(types);

			// вызвать конструктор
			return (Choice)constructor.newInstance(args); 
		}
        // при ошибке выбросить исключение
        catch (Exception e) { throw new RuntimeException(e); }
    }
}