package aladdin.asn1.ansi.x957; 
import aladdin.asn1.*; 
import aladdin.asn1.Integer; 
import java.io.*; 

// DssSigValue ::= SEQUENCE {
//		r            INTEGER,
//		s            INTEGER
// }

public final class DssSigValue extends Sequence<Integer>
{
    private static final long serialVersionUID = -8928732534194593289L;
    
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(Integer.class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(Integer.class).factory(), Cast.N), 
	}; 
	// конструктор при раскодировании
	public DssSigValue(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public DssSigValue(Integer r, Integer s) { super(info, r, s); }

	public final Integer r() { return get(0); }
	public final Integer s() { return get(1); }
}
