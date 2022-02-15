namespace Aladdin.ASN1.STB
{
    ///////////////////////////////////////////////////////////////////////////////
    // BDSBDHParams ::= CHOICE {
    //		bdsbdhParamsReference OBJECT IDENTIFIER,
    //		bdsbdhParamsList BDSBDHParamsList
    //	}
    ///////////////////////////////////////////////////////////////////////////////
    public class BDSBDHParams : Choice
    {
	    // информация о структуре
	    private static readonly ObjectInfo[] info = new ObjectInfo[] { 

		    new ObjectInfo(new ObjectCreator<ObjectIdentifier>().Factory(), Cast.N), 
		    new ObjectInfo(new ObjectCreator<BDSBDHParamsList>().Factory(), Cast.N), 
	    }; 
	    // конструктор
	    public BDSBDHParams() : base(info) {} 
    }
}
