package aladdin.asn1.iso.pkix;
import aladdin.asn1.*; 

//	AttributeCertIssuer ::= CHOICE {
//		v1Form					GeneralNames,
//		v2Form   [0] IMPLICIT	AttrributeGeneralNames 
// }

public final class AttributeIssuer extends Choice
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(GeneralNames		  .class).factory(), Cast.N, Tag.ANY		 ), 
		new ObjectInfo(new ObjectCreator(AttributeGeneralNames.class).factory(), Cast.N, Tag.context(0)), 
	}; 
	// конструктор
	public AttributeIssuer() { super(info); } 
}
