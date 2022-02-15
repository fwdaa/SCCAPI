namespace Aladdin.ASN1.ANSI.X962
{
    ////////////////////////////////////////////////////////////////////////////////
    // EcpkParameters ::= CHOICE {
    //      ecParameters  ECParameters,
    //      namedCurve    OBJECT IDENTIFIER,
    //      implicitlyCA  NULL 
    // }
    ////////////////////////////////////////////////////////////////////////////////
    public class ECDomainParameters : Choice
    {
	    // информация о структуре
	    private static readonly ObjectInfo[] info = new ObjectInfo[] { 

		    new ObjectInfo(new ObjectCreator<SpecifiedECDomain>().Factory(), Cast.N), 
		    new ObjectInfo(new ObjectCreator<ObjectIdentifier >().Factory(), Cast.N), 
		    new ObjectInfo(new ObjectCreator<Null             >().Factory(), Cast.N), 
	    }; 
	    // конструктор
	    public ECDomainParameters() : base(info) {} 
    }
}
