using System; 
using System.Runtime.Serialization;

namespace Aladdin.ASN1.ANSI.X962
{
    ////////////////////////////////////////////////////////////////////////////////
    // ECWKTParameters ::= SEQUENCE {
    //      kdf  [0] EXPLICIT KeyDerivationFunction OPTIONAL,
    //      wrap [1] EXPLICIT KeyWrapFunction OPTIONAL
    // }
    ////////////////////////////////////////////////////////////////////////////////
	[Serializable]
    public class ECWKTParameters : Sequence
    {
	    // информация о структуре
	    private static readonly ObjectInfo[] info = new ObjectInfo[] { 

		    new ObjectInfo(new ObjectCreator<ISO.AlgorithmIdentifier>().Factory(), Cast.EO, Tag.Context(0)), 
		    new ObjectInfo(new ObjectCreator<ISO.AlgorithmIdentifier>().Factory(), Cast.EO, Tag.Context(1)) 
	    }; 
		// конструктор при сериализации
        protected ECWKTParameters(SerializationInfo info, StreamingContext context) : base(info, context) {}

	    // конструктор при раскодировании
	    public ECWKTParameters(IEncodable encodable) : base(encodable, info) {}

	    // конструктор при закодировании
	    public ECWKTParameters(ISO.AlgorithmIdentifier kdf, ISO.AlgorithmIdentifier wrap) 
            : base(info, kdf, wrap) {} 

	    public ISO.AlgorithmIdentifier Kdf  { get { return (ISO.AlgorithmIdentifier)this[0]; }}
	    public ISO.AlgorithmIdentifier Wrap { get { return (ISO.AlgorithmIdentifier)this[1]; }}
    }
}
