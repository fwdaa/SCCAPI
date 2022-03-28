package aladdin.asn1.ansi.x962;
import aladdin.asn1.*; 
import java.io.*; 

////////////////////////////////////////////////////////////////////////////////
// NamedMultiples ::= SEQUENCE {
//      multiples OBJECT IDENTIFIER,
//      points SEQUENCE OF ECPoint
// }
////////////////////////////////////////////////////////////////////////////////
public final class NamedMultiples extends Sequence<IEncodable>
{
    private static final long serialVersionUID = -1674455961452205636L;
    
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(ObjectIdentifier.class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(ECPoints        .class).factory(), Cast.N), 
	}; 
	// конструктор при раскодировании
	public NamedMultiples(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public NamedMultiples(ObjectIdentifier multiples, ECPoints points) { super(info, multiples, points); }

	public final ObjectIdentifier multiples() { return (ObjectIdentifier)get(0); }
	public final ECPoints         points   () { return (ECPoints        )get(1); }
}
