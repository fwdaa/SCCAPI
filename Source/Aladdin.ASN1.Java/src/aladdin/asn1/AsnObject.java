package aladdin.asn1;
import java.util.*; 
import java.io.*; 
import java.lang.reflect.*; 

///////////////////////////////////////////////////////////////////////////
// Известный объект ASN.1
///////////////////////////////////////////////////////////////////////////
public abstract class AsnObject implements IEncodable
{
    private static final long serialVersionUID = -417216351471319950L;

    // конструктор при раскодировании
    protected AsnObject(IEncodable encodable)
    {
    	this.tag = encodable.tag();  // тип объекта
    	this.ber = encodable;        // закодированное BER-представление
    	this.der = null;             // закодированное DER-представление
    }
    // конструктор при закодировании
    protected AsnObject(Tag tag)
    {
    	this.tag = tag;              // тип объекта
        this.ber = null;             // закодированное BER-представление
		this.der = null;             // закодированное DER-представление
    }
    // атрибуты объекта
    @Override public final Tag    tag    () { return berEncodable().tag    (); }
    @Override public final PC     pc     () { return berEncodable().pc     (); }
    @Override public final byte[] content() { return berEncodable().content(); }
    @Override public final byte[] encoded() { return berEncodable().encoded(); }
    
    // способ кодирования и содержимое объекта
    protected abstract PC       derPC     ();
    protected abstract byte[]   derContent();

    private IEncodable berEncodable()
    {
		// вернуть закодированное BER-представление
		if (ber == null) ber = derEncodable(); return ber;
    }
    public IEncodable derEncodable()
    {
		// вернуть закодированное DER-представление
		if (der == null) der = Encodable.encode(tag, derPC(), derContent()); return der;
    }
    private Tag        tag; // тип объекта
    private IEncodable ber; // закодированное BER-представление
    private IEncodable der; // закодированное DER-представление

    /////////////////////////////////////////////////////////////////////////////
    // Сериализация
    /////////////////////////////////////////////////////////////////////////////
    protected void writeObject(ObjectOutputStream oos) throws IOException 
    {
        // записать закодированное представление
        oos.writeObject(encoded()); 
    }
    protected void readObject(ObjectInputStream ois) throws IOException 
    {
        try { 
            // получить конструктор при раскодировании
            Constructor<?> constructor = getClass().getConstructor(IEncodable.class); 
            
            // раскодировать представление
            IEncodable encodable = Encodable.decode((byte[])ois.readObject()); 
            
            // создать объект 
            AsnObject instance = (AsnObject)constructor.newInstance(encodable); 

            // сохранить переменные объекта
            this.tag = instance.tag(); ber = instance.berEncodable(); der = instance.derEncodable(); 
        }
        // обработать возможную ошибку
        catch (ClassNotFoundException    e) { throw new IOException(e); }
        catch (NoSuchMethodException     e) { throw new IOException(e); }
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
    }    
    /////////////////////////////////////////////////////////////////////////////
    // Сравнить два объекта
    /////////////////////////////////////////////////////////////////////////////
    @Override public int hashCode()
    {
		// получить хэш-код объекта
		return derEncodable().encoded()[0];
    }
    @Override public boolean equals(Object obj)
    {
    	// сравнить два объекта
    	return (obj instanceof IEncodable) ? equals((IEncodable)obj) : false;
    }
    public final boolean equals(IEncodable obj)
    {
		// выполнить тривиальные проверки
		if (obj == null) return false; if (this == obj) return true;

		// сравнить два объекта
		if (obj instanceof AsnObject) return equals((AsnObject)obj);

		// сравнить два объекта
		return Arrays.equals(derEncodable().encoded(), obj.encoded());
    }
    public final boolean equals(AsnObject obj)
    {
		// выполнить тривиальные проверки
		if (obj == null) return false; if (this == obj) return true;

		// сравнить два объекта
		return Arrays.equals(derEncodable().encoded(), obj.derEncodable().encoded());
    }
}