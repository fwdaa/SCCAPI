package aladdin.capi.jcp;
import java.security.*; 
import java.lang.reflect.*; 
import java.util.*; 

///////////////////////////////////////////////////////////////////////////
// Сервис алгоритма криптопровайдера
///////////////////////////////////////////////////////////////////////////
public class Service // extends Provider.Service
{
/*	// параметры вызова
    @SuppressWarnings("rawtypes") 
	private final Class type; private final Object[] args;  
	
    @SuppressWarnings("rawtypes") 
	public Service(Provider provider, String kind, String name, String aliase, 
		Class type, Object... args)
	{
		// вызвать базовую функцию
		super(provider, kind, name, "*", Arrays.asList(new String[] {aliase}), null); 
		
		// сохранить аргументы 
		this.type = type; this.args = args;  
	}
    @SuppressWarnings("rawtypes") 
	public Service(Provider provider, String kind, String name, 
		Class type, Object... args)
	{
		// вызвать базовую функцию
		super(provider, kind, name, "*", null, null); 
		
		// сохранить аргументы 
		this.type = type; this.args = args;  
	}
	@Override
	public final boolean supportsParameter(Object obj) 
	{
		// проверить тип ключа
		if (!(obj instanceof java.security.Key)) return false;

		// преобразовать тип провайдера
		Provider provider = (Provider)getProvider(); 
		
		// преобразовать тип ключа
		java.security.Key key = (java.security.Key)obj; 
		
		// создать алгоритм вычисления имитовставки
		try { new KeyFactorySpi(provider).engineTranslateKey(key); return true; } 
		
		// обработать возможное исключение
		catch (Throwable e) { return false; }
	}
	@Override
    @SuppressWarnings({"unchecked"}) 
	public final Object newInstance(Object parameter) throws NoSuchAlgorithmException
	{
		// скопировать переданный параметр
		Object[] parameters = (parameter != null) ? new Object[] {parameter} : new Object[0]; 
		
		// выделить память для параметров
		Object[] args = new Object[parameters.length + this.args.length];
		
		// скопировать параметры 
		System.arraycopy(parameters, 0, args, 0, parameters.length);
		
		// скопировать параметры 
		System.arraycopy(this.args, 0, args, parameters.length, this.args.length);
		try { 
			// получить доступные конструкторы
			Constructor[] constructors = type.getConstructors(); 
		
			// для каждого конструктора
			for (Constructor constructor : constructors)
			{
				// получить аргументы конструктора
				Class[] types = constructor.getParameterTypes(); 
			
				// проверить число параметров
				if (types.length != args.length) continue; boolean find = true; 
			
				// для каждого параметра
				for (int i = 0; i < types.length; i++)
				{
					// проверить соответствие параметра
					if (!types[i].isAssignableFrom(args[i].getClass())) { find = false; break; }
				}
				// проверить нахождение конструктора
				if (!find) continue; switch (args.length)
				{
				// вызвать конструктор
				case 0: return constructor.newInstance(                         ); 
				case 1: return constructor.newInstance(args[0]                  );
				case 2: return constructor.newInstance(args[0], args[1]         );
				case 3: return constructor.newInstance(args[0], args[1], args[2]);
				}
			}
		}
		// обработать возможное исключение
		catch (Throwable e) {} throw new NoSuchAlgorithmException();
	}
*/}
