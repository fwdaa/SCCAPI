using System; 

// Skipjack-Parm ::= SEQUENCE { initialization-vector   OCTET STRING }

namespace Aladdin.ASN1.ANSI
{
    public class SkipjackParm : Sequence
    {
	    // информация о структуре
	    private static readonly ObjectInfo[] info = new ObjectInfo[] { 

            new ObjectInfo(new ObjectCreator<OctetString>().Factory(), Cast.N), 
	    }; 
	    // конструктор при раскодировании
	    public SkipjackParm(IEncodable encodable) : base(encodable, info) {}

	    // конструктор при закодировании
	    public SkipjackParm(OctetString iv) : base(info, iv) {}
    
	    public OctetString IV { get { return (OctetString)this[0]; }}
    }
}