package aladdin.asn1;
import java.io.*; 
import java.math.*; 

///////////////////////////////////////////////////////////////////////////
// Значение перечислимого типа
///////////////////////////////////////////////////////////////////////////
public final class Enumerated extends Integer
{
    // private static final long serialVersionUID = 1841353454133299997L;
    
    // проверить допустимость типа
    public static boolean isValidTag(Tag tag) { return tag.equals(Tag.ENUMERATED); }
    
    // конструктор при раскодировании
	public Enumerated(IEncodable encodable) throws IOException { super(encodable); }

	// конструктор при закодировании
	public Enumerated(BigInteger value) { super(Tag.ENUMERATED, value); }
		
	// конструктор при закодировании
	public Enumerated(int value) { this(BigInteger.valueOf(value)); } 
}
