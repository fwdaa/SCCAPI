using System; 
using System.Runtime.Serialization;

namespace Aladdin.ASN1.ANSI.X962
{
    ////////////////////////////////////////////////////////////////////////////////
    // Pentanomial ::= SEQUENCE {
    //      k1  INTEGER,
    //      k2  INTEGER,
    //      k3  INTEGER 
    // }
    ////////////////////////////////////////////////////////////////////////////////
	[Serializable]
    public class Pentanomial : Sequence
    {
	    // информация о структуре
	    private static readonly ObjectInfo[] info = new ObjectInfo[] { 

		    new ObjectInfo(new ObjectCreator<Integer>().Factory(), Cast.N), 
		    new ObjectInfo(new ObjectCreator<Integer>().Factory(), Cast.N), 
		    new ObjectInfo(new ObjectCreator<Integer>().Factory(), Cast.N) 
	    }; 
		// конструктор при сериализации
        protected Pentanomial(SerializationInfo info, StreamingContext context) : base(info, context) {}

	    // конструктор при раскодировании
	    public Pentanomial(IEncodable encodable) : base(encodable, info) {}

	    // конструктор при закодировании
	    public Pentanomial(Integer k1, Integer k2, Integer k3) : base(info, k1, k2, k3) {}

	    public Integer K1 { get { return (Integer)this[0]; }}
	    public Integer K2 { get { return (Integer)this[1]; }}
	    public Integer K3 { get { return (Integer)this[2]; }}
    }
}
