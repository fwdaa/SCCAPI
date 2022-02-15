package aladdin.asn1;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Объект с явным приведением типа от произвольного типа
///////////////////////////////////////////////////////////////////////////
public class Explicit<T extends IEncodable> extends Encodable
{
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
    public final T inner() { return value; } private final T value;
}