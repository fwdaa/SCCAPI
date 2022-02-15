package aladdin.asn1.iso.pkix;
import aladdin.asn1.*; 
import aladdin.asn1.iso.pkix.x400.*;

//	GeneralName ::= CHOICE {
//		otherName                 [0] IMPLICIT AnotherName,
//		rfc822Name                [1] IMPLICIT IA5String,
//		dNSName                   [2] IMPLICIT IA5String,
//		x400Address               [3] IMPLICIT ORAddress,
//		directoryName             [4] IMPLICIT Name,
//		ediPartyName              [5] IMPLICIT EDIPartyName,
//		uniformResourceIdentifier [6] IMPLICIT IA5String,
//		iPAddress                 [7] IMPLICIT OCTET STRING,
//		registeredID              [8] IMPLICIT OBJECT IDENTIFIER 
//	}

public final class GeneralName extends Choice
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(    ImplicitCreator			               .factory  , Cast.N, Tag.context(0)), 
		new ObjectInfo(new ObjectCreator(IA5String          .class).factory(), Cast.N, Tag.context(1)), 
		new ObjectInfo(new ObjectCreator(IA5String          .class).factory(), Cast.N, Tag.context(2)), 
		new ObjectInfo(new ObjectCreator(OrAddress          .class).factory(), Cast.N, Tag.context(3)), 
		new ObjectInfo(new ChoiceCreator(Name               .class).factory(), Cast.N, Tag.context(4)), 
		new ObjectInfo(new ObjectCreator(EDIPartyName       .class).factory(), Cast.N, Tag.context(5)), 
		new ObjectInfo(new ObjectCreator(IA5String          .class).factory(), Cast.N, Tag.context(6)), 
		new ObjectInfo(new ObjectCreator(OctetString        .class).factory(), Cast.N, Tag.context(7)), 
		new ObjectInfo(new ObjectCreator(ObjectIdentifier   .class).factory(), Cast.N, Tag.context(8)), 
	}; 
	// конструктор
	public GeneralName() { super(info); } 
}
