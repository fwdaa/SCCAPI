package aladdin.asn1.ansi.x962;
import aladdin.asn1.*; 
import aladdin.asn1.Integer; 
import java.io.*; 

////////////////////////////////////////////////////////////////////////////////
// SpecifiedMultiples ::= SEQUENCE {
//      multiple INTEGER,
//      point ECPoint 
// }
////////////////////////////////////////////////////////////////////////////////
public final class SpecifiedMultiple extends Sequence<IEncodable>
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(Integer    .class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(OctetString.class).factory(), Cast.N), 
	}; 
	// конструктор при раскодировании
	public SpecifiedMultiple(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public SpecifiedMultiple(Integer multiple, OctetString point) { super(info, multiple, point); }

	public final Integer     multiple() { return (Integer    )get(0); }
	public final OctetString point   () { return (OctetString)get(1); }
}
