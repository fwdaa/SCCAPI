package aladdin.asn1.ansi.x962;
import aladdin.asn1.*; 
import java.io.*; 

////////////////////////////////////////////////////////////////////////////////
// FieldElement ::= OCTET STRING
// Curve ::= SEQUENCE {
//      a FieldElement,
//      b FieldElement,
//      seed BIT STRING OPTIONAL
// }
////////////////////////////////////////////////////////////////////////////////
public final class Curve extends Sequence<IEncodable>
{
    private static final long serialVersionUID = 2801992130222585299L;
    
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 
        
		new ObjectInfo(new ObjectCreator(OctetString.class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(OctetString.class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(BitString  .class).factory(), Cast.O), 
	}; 
	// конструктор при раскодировании
	public Curve(IEncodable encodable) throws IOException { super(encodable, info); } 
    
	// конструктор при закодировании
	public Curve(OctetString a, OctetString b, BitString seed) { super(info, a, b, seed); }

    public final OctetString a   () { return (OctetString)get(0); } 
	public final OctetString b   () { return (OctetString)get(1); } 
	public final BitString   seed() { return (BitString  )get(2); } 
}
