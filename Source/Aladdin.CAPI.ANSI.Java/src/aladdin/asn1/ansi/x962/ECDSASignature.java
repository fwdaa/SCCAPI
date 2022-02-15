package aladdin.asn1.ansi.x962;
import aladdin.asn1.*; 

////////////////////////////////////////////////////////////////////////////////
// ECDSA-Signature ::= CHOICE {
//      two-ints-plus ECDSA-Sig-Value,
//      point-int [0] EXPLICIT ECDSA-Full-R,
// }
////////////////////////////////////////////////////////////////////////////////
public final class ECDSASignature extends Choice
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(ECDSASigValue.class).factory(), Cast.N, Tag.ANY       ), 
		new ObjectInfo(new ObjectCreator(ECDSAFullR   .class).factory(), Cast.E, Tag.context(0)) 
	}; 
	// конструктор
	public ECDSASignature() { super(info); } 
}
