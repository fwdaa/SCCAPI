package aladdin.asn1.iso.pkix.ce;
import aladdin.asn1.*; 
import aladdin.asn1.iso.pkix.*; 

//	DistributionPointName ::= CHOICE {
//		fullName                [0] IMPLICIT GeneralNames,
//		nameRelativeToCRLIssuer [1] IMPLICIT RelativeDistinguishedName 
//	}

public final class DistributionPointName extends Choice
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(GeneralNames               .class).factory(), Cast.N, Tag.context(0)), 
		new ObjectInfo(new ObjectCreator(RelativeDistinguishedName  .class).factory(), Cast.N, Tag.context(1)), 
	}; 
	// конструктор
	public DistributionPointName() { super(info); } 
}
