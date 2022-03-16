using System; 
using System.Runtime.Serialization;

namespace Aladdin.ASN1.ANSI.X962
{
    ////////////////////////////////////////////////////////////////////////////////
    // ECIESParameters ::= SEQUENCE {
    //      kdf [0] EXPLICIT KeyDerivationFunction OPTIONAL,
    //      sym [1] EXPLICIT SymmetricEncryption OPTIONAL,
    //      mac [2] EXPLICIT MessageAuthenticationCode OPTIONAL
    // }
    ////////////////////////////////////////////////////////////////////////////////
	[Serializable]
    public class ECIESParameters : Sequence
    {
	    // информация о структуре
	    private static readonly ObjectInfo[] info = new ObjectInfo[] { 

		    new ObjectInfo(new ObjectCreator<ISO.AlgorithmIdentifier>().Factory(), Cast.EO, Tag.Context(0)), 
		    new ObjectInfo(new ObjectCreator<ISO.AlgorithmIdentifier>().Factory(), Cast.EO, Tag.Context(1)), 
		    new ObjectInfo(new ObjectCreator<ISO.AlgorithmIdentifier>().Factory(), Cast.EO, Tag.Context(2)), 
	    }; 
		// конструктор при сериализации
        protected ECIESParameters(SerializationInfo info, StreamingContext context) : base(info, context) {}

	    // конструктор при раскодировании
	    public ECIESParameters(IEncodable encodable) : base(encodable, info) {}

	    // конструктор при закодировании
	    public ECIESParameters(ISO.AlgorithmIdentifier kdf, 
            ISO.AlgorithmIdentifier sym, ISO.AlgorithmIdentifier mac) : base(info, kdf, sym, mac) {}

	    public ISO.AlgorithmIdentifier Kdf { get { return (ISO.AlgorithmIdentifier)this[0]; }}
	    public ISO.AlgorithmIdentifier Sym { get { return (ISO.AlgorithmIdentifier)this[1]; }}
	    public ISO.AlgorithmIdentifier Mac { get { return (ISO.AlgorithmIdentifier)this[2]; }}
    }
}