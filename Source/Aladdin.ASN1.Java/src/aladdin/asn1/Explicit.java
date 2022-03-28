package aladdin.asn1;
import java.io.*; 
import java.lang.reflect.*; 

///////////////////////////////////////////////////////////////////////////
// Объект с явным приведением типа от произвольного типа
///////////////////////////////////////////////////////////////////////////
public class Explicit<T extends IEncodable> extends Encodable
{
    private static final long serialVersionUID = 6920194995374770790L;

    // закодировать объект
	public static IEncodable encode(Tag tag, IEncodable encodable)
	{
		// закодировать объект
		return Encodable.encode(tag, PC.CONSTRUCTED, encodable.encoded()); 
	}
    // конструктор при раскодировании
    public Explicit(Class<? extends T> type, IEncodable encodable) throws IOException
    {
    	this(new ObjectCreator(type).factory(), encodable);
    }
    // конструктор при раскодировании
    @SuppressWarnings({"unchecked"}) 
    public Explicit(IObjectFactory<? extends IEncodable> factory, IEncodable encodable) throws IOException
    {
		// раскодировать внутренний объект
		super(encodable); value = (T)factory.decode(Encodable.decode(encodable.content()));
    }
    // конструктор при закодировании
    public Explicit(Class<? extends T>  type, Tag tag, IEncodable value) 
    {
    	this(new ObjectCreator(type).factory(), tag, value);
    }
    // конструктор при закодировании
    @SuppressWarnings({"unchecked"}) 
    public Explicit(IObjectFactory<? extends IEncodable> factory, Tag tag, IEncodable value) 
    {
        // проверить корректность объекта
		super(tag, PC.CONSTRUCTED); try { this.value = (T)factory.decode(value); }
		
		// обработать возможное исключение
		catch (IOException e) { throw new IllegalArgumentException(e); }
    }
    // содержимое объекта
    @Override protected final byte[] evaluateContent() { return value.encoded(); }

    // исходный объект
    public final T inner() { return value; } private T value;
    
    /////////////////////////////////////////////////////////////////////////////
    // Сериализация
    /////////////////////////////////////////////////////////////////////////////
    @Override protected void writeObject(ObjectOutputStream oos) throws IOException 
    {
        // вызвать базовую функцию
        super.writeObject(oos); 
        try { 
            // проверить наличие конструктора
            getClass().getConstructor(IEncodable.class); 
        }
        // записать закодированное представление
        catch (NoSuchMethodException e) { oos.writeObject(value); }
    }
    @SuppressWarnings({"rawtypes", "unchecked"}) 
    @Override protected void readObject(ObjectInputStream ois) throws IOException 
    {
        // вызвать базовую функцию
        super.readObject(ois); 
        try { 
            // получить конструктор при раскодировании
            Constructor constructor = getClass().getConstructor(IEncodable.class); 
            
            // создать объект 
            Explicit<T> instance = (Explicit<T>)constructor.newInstance(this); 

            // сохранить переменные объекта
            this.value = instance.value; 
        }
        // обработать возможную ошибку
		catch (InstantiationException    e) { throw new IOException(e); }
		catch (IllegalAccessException    e) { throw new IOException(e); }
		catch (InvocationTargetException e) 
        { 
            // получить внутреннее исключение 
            Throwable inner = e.getCause(); 
            
            // проверить тип исключения 
            if (inner instanceof IOException) throw (IOException)inner; 
            
            // выбросить исключение 
            throw new IOException(inner);
        }
        catch (NoSuchMethodException  e) 
        {
            // прочитать представление
            try { value = (T)ois.readObject(); } 
            
            // обработать возможное исключение
            catch (ClassNotFoundException ex) { throw new IOException(ex); }
        }
    }    
}
