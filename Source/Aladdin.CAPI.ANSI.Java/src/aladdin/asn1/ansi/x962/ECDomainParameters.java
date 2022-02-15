package aladdin.asn1.ansi.x962;
import aladdin.asn1.*; 

////////////////////////////////////////////////////////////////////////////////
// EcpkParameters ::= CHOICE {
//      ecParameters  ECParameters,
//      namedCurve    OBJECT IDENTIFIER,
//      implicitlyCA  NULL 
// }
////////////////////////////////////////////////////////////////////////////////
public final class ECDomainParameters extends Choice
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(SpecifiedECDomain.class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(ObjectIdentifier .class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(Null             .class).factory(), Cast.N), 
	}; 
	// конструктор
	public ECDomainParameters() { super(info); } 
}
