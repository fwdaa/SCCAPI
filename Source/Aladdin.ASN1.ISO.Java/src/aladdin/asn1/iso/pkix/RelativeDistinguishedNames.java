package aladdin.asn1.iso.pkix;
import aladdin.asn1.*; 
import java.io.*; 
import java.lang.reflect.*; 

// RelativeDistinguishedNames ::= SEQUENCE OF RelativeDistinguishedName

public final class RelativeDistinguishedNames extends Sequence<RelativeDistinguishedName>
{
    private static final long serialVersionUID = -5992734150333846734L;
    
    // закодировать строковое имя
    private static IEncodable encodeName(String name) throws IOException
    {
        // указать загрузчик классов
        ClassLoader classLoader = RelativeDistinguishedNames.class.getClassLoader(); 
        try { 
            // найти класс объекта
            Class<?> type = classLoader.loadClass("javax.security.auth.x500.X500Principal"); 
            
            // найти конструктор типа
            Constructor<?> constructor = type.getConstructor(String.class); 
            
            // создать объект имени
            Object principal = constructor.newInstance(name); 
            
            // найти требуемый метод
            Method method = principal.getClass().getMethod("getEncoded"); 
            
            // вызвать требуемый метод
            return Encodable.decode((byte[])method.invoke(principal)); 
        }
        // обработать возможное исключение
        catch (ClassNotFoundException    e) { throw new IOException(e); }
        catch (NoSuchMethodException     e) { throw new IOException(e); }
        catch (InstantiationException    e) { throw new IOException(e); }
        catch (IllegalAccessException    e) { throw new IOException(e); }
        catch (InvocationTargetException e) { throw new IOException(e); }
    }
    // раскодировать строковое имя 
    private static String decodeName(IEncodable encodable) throws IOException
    {
        // указать загрузчик классов
        ClassLoader classLoader = RelativeDistinguishedNames.class.getClassLoader(); 
        try { 
            // найти класс объекта
            Class<?> type = classLoader.loadClass("javax.security.auth.x500.X500Principal"); 
            
            // найти конструктор типа
            Constructor<?> constructor = type.getConstructor(byte[].class); 
            
            // создать объект имени
            Object principal = constructor.newInstance(encodable.encoded()); 
            
            // найти требуемый метод
            Method method = principal.getClass().getMethod("getName"); 
            
            // вызвать требуемый метод
            return (String)method.invoke(principal); 
        }
        // обработать возможное исключение
        catch (ClassNotFoundException    e) { throw new IOException(e); }
        catch (NoSuchMethodException     e) { throw new IOException(e); }
        catch (InstantiationException    e) { throw new IOException(e); }
        catch (IllegalAccessException    e) { throw new IOException(e); }
        catch (InvocationTargetException e) { throw new IOException(e); }
    }
	// конструктор при раскодировании
	public RelativeDistinguishedNames(IEncodable encodable) throws IOException
	{
		super(RelativeDistinguishedName.class, encodable); init(); 
	}
	// конструктор при закодировании
	public RelativeDistinguishedNames(RelativeDistinguishedName... values) throws IOException
	{
		super(RelativeDistinguishedName.class, values); init();
	}
	// конструктор по строковому имени
	public RelativeDistinguishedNames(String name) throws IOException
    {	
		// закодировать строко
		super(encodeName(name)); this.name = name; 
    }
	// извлечь строковое имя 
	private void init() throws IOException { name = decodeName(this); }
    
	// раскодированное значение атрибута
	@Override public String toString() { return name; } private String name; 
}
