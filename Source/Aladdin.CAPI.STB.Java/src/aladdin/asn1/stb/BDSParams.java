package aladdin.asn1.stb;
import aladdin.asn1.*; 

///////////////////////////////////////////////////////////////////////////////
// BDSParams ::= CHOICE {
// 		bdsParamsReference OBJECT IDENTIFIER,
// 		bdsParamsList BDSParamsList
// 	}
///////////////////////////////////////////////////////////////////////////////
public final class BDSParams extends Choice
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(ObjectIdentifier.class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(BDSParamsList	 .class).factory(), Cast.N), 
	}; 
	// конструктор
	public BDSParams() { super(info); } 
}
