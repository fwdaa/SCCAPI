using System; 
using System.Runtime.Serialization;

// Skipjack-Parm ::= SEQUENCE { initialization-vector   OCTET STRING }

namespace Aladdin.ASN1.ANSI
{
	[Serializable]
    public class SkipjackParm : Sequence
    {
	    // информация о структуре
	    private static readonly ObjectInfo[] info = new ObjectInfo[] { 

            new ObjectInfo(new ObjectCreator<OctetString>().Factory(), Cast.N), 
	    }; 
		// конструктор при сериализации
        protected SkipjackParm(SerializationInfo info, StreamingContext context) : base(info, context) {}

	    // конструктор при раскодировании
	    public SkipjackParm(IEncodable encodable) : base(encodable, info) {}

	    // конструктор при закодировании
	    public SkipjackParm(OctetString iv) : base(info, iv) {}
    
	    public OctetString IV { get { return (OctetString)this[0]; }}
    }
}