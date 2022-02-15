package aladdin.asn1.stb;
import aladdin.asn1.*; 

////////////////////////////////////////////////////////////////////////////////
// DomainParameters ::= CHOICE {
//      specified ECParameters,
//      named OBJECT IDENTIFIER,
//      implicit NULL
// }
////////////////////////////////////////////////////////////////////////////////
public final class DomainParameters extends Choice
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(ECParameters    .class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(ObjectIdentifier.class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(Null            .class).factory(), Cast.N), 
	}; 
	// конструктор
	public DomainParameters() { super(info); } 
}
