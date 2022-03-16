using System; 
using System.Runtime.Serialization;

namespace Aladdin.ASN1.ANSI.X962
{
    ////////////////////////////////////////////////////////////////////////////////
    // NamedMultiples ::= SEQUENCE {
    //      multiples OBJECT IDENTIFIER,
    //      points SEQUENCE OF ECPoint
    // }
    ////////////////////////////////////////////////////////////////////////////////
	[Serializable]
    public class NamedMultiples : Sequence
    {
	    // информация о структуре
	    private static readonly ObjectInfo[] info = new ObjectInfo[] { 

		    new ObjectInfo(new ObjectCreator<ObjectIdentifier>().Factory(), Cast.N), 
		    new ObjectInfo(new ObjectCreator<ECPoints        >().Factory(), Cast.N), 
	    }; 
		// конструктор при сериализации
        protected NamedMultiples(SerializationInfo info, StreamingContext context) : base(info, context) {}

	    // конструктор при раскодировании
	    public NamedMultiples(IEncodable encodable) : base(encodable, info) {}

	    // конструктор при закодировании
	    public NamedMultiples(ObjectIdentifier multiples, ECPoints points) : base(info, multiples, points) {}

	    public ObjectIdentifier Multiples { get { return (ObjectIdentifier)this[0]; }}
	    public ECPoints         Points    { get { return (ECPoints        )this[1]; }}
    }
}
