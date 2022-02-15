using System; 
using System.Collections.Generic; 

namespace Aladdin.ASN1.STB
{
    ///////////////////////////////////////////////////////////////////////////////
    // SBlockTable ::= OCTET STRING (SIZE(64))
    // SBlock ::= CHOICE {
    // 	table SBlockTable,
    // 	oid OBJECT IDENTIFIER
    // }
    ///////////////////////////////////////////////////////////////////////////////
    public class SBlock : Choice
    {
	    // информация о структуре
	    private static readonly ObjectInfo[] info = new ObjectInfo[] { 

		    new ObjectInfo(new ObjectCreator<OctetString     >().Factory(64, 64), Cast.N), 
		    new ObjectInfo(new ObjectCreator<ObjectIdentifier>().Factory(      ), Cast.N), 
	    }; 
	    // конструктор
	    public SBlock() : base(info) {} 
    }
}