package aladdin.asn1.ansi.x962; 
import aladdin.asn1.*; 
import aladdin.asn1.Integer; 
import java.io.*; 

////////////////////////////////////////////////////////////////////////////////
// Pentanomial ::= SEQUENCE {
//      k1  INTEGER,
//      k2  INTEGER,
//      k3  INTEGER 
// }
////////////////////////////////////////////////////////////////////////////////
public final class Pentanomial extends Sequence<Integer>
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(Integer.class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(Integer.class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(Integer.class).factory(), Cast.N) 
	}; 
	// конструктор при раскодировании
	public Pentanomial(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public Pentanomial(Integer k1, Integer k2, Integer k3) { super(info, k1, k2, k3); }

	public final Integer k1() { return get(0); }
	public final Integer k2() { return get(1); }
	public final Integer k3() { return get(2); }
}
