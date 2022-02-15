package aladdin.asn1.stb;
import aladdin.asn1.*; 

///////////////////////////////////////////////////////////////////////////////
// BDSBDHParams ::= CHOICE {
//		bdsbdhParamsReference OBJECT IDENTIFIER,
//		bdsbdhParamsList BDSBDHParamsList
//	}
///////////////////////////////////////////////////////////////////////////////
public final class BDSBDHParams extends Choice
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(ObjectIdentifier.class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(BDSBDHParamsList.class).factory(), Cast.N), 
	}; 
	// конструктор
	public BDSBDHParams() { super(info); } 
}
