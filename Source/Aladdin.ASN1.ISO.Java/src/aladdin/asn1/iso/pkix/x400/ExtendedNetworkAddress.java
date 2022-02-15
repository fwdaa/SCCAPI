package aladdin.asn1.iso.pkix.x400;
import aladdin.asn1.*; 

// ExtendedNetworkAddress ::= CHOICE {
//  e163-4-address E163-4-address,
//  psap-address   [0] IMPLICIT PresentationAddress 
// }

public final class ExtendedNetworkAddress extends Choice
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(E1634Address       .class).factory(), Cast.N, Tag.context(0)), 
		new ObjectInfo(new ObjectCreator(PresentationAddress.class).factory(), Cast.O, Tag.context(1)), 
	}; 
	// конструктор 
	public ExtendedNetworkAddress() { super(info); } 
}
