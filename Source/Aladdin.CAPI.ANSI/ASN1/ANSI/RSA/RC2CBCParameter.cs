///////////////////////////////////////////////////////////////////////////////
// RC2-CBCParameter ::= CHOICE {
//      iv OCTET STRING(8),
//      params SEQUENCE {
//          version INTEGER,
//          iv OCTET STRING(8)
//  }
// }
///////////////////////////////////////////////////////////////////////////////
namespace Aladdin.ASN1.ANSI.RSA
{
    public class RC2CBCParameter : Choice
    {
	    // информация о структуре
	    private static readonly ObjectInfo[] info = new ObjectInfo[] { 

		    new ObjectInfo(new ObjectCreator<OctetString >().Factory(8, 8), Cast.N), 
		    new ObjectInfo(new ObjectCreator<RC2CBCParams>().Factory(    ), Cast.N), 
	    }; 
	    // конструктор
	    public RC2CBCParameter() : base(info) {} 
    }
}
