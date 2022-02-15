namespace Aladdin.ASN1.STB
{
    ///////////////////////////////////////////////////////////////////////////////
    // BDHParams ::= CHOICE {
    // 		bdhParamsReference OBJECT IDENTIFIER,
    // 		bdhParamsList BDHParamsList
    // 	}
    ///////////////////////////////////////////////////////////////////////////////
    public class BDHParams : Choice
    {
	    // информация о структуре
	    private static readonly ObjectInfo[] info = new ObjectInfo[] { 

		    new ObjectInfo(new ObjectCreator<ObjectIdentifier>().Factory(), Cast.N), 
		    new ObjectInfo(new ObjectCreator<BDSParamsList	 >().Factory(), Cast.N), 
	    }; 
	    // конструктор
	    public BDHParams() : base(info) {} 
    }
}
