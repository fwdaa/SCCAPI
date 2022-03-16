using System; 
using System.Runtime.Serialization;

namespace Aladdin.ASN1.ANSI.X962
{
    ////////////////////////////////////////////////////////////////////////////////
    // MQVUserKeyingMaterial ::= SEQUENCE {
    //         ephemeralPublicKey OriginatorPublicKey,
    //         addedukm [0] EXPLICIT UserKeyingMaterial OPTIONAL  
    // }
    ////////////////////////////////////////////////////////////////////////////////
	[Serializable]
    public class MQVUserKeyingMaterial : Sequence
    {
	    // информация о структуре
	    private static readonly ObjectInfo[] info = new ObjectInfo[] { 

		    new ObjectInfo(new ObjectCreator<ISO.AlgorithmIdentifier>().Factory(), Cast.N , Tag.Any       ), 
		    new ObjectInfo(new ObjectCreator<OctetString            >().Factory(), Cast.EO, Tag.Context(0)) 
	    };
		// конструктор при сериализации
        protected MQVUserKeyingMaterial(SerializationInfo info, StreamingContext context) : base(info, context) {}

	    // конструктор при раскодировании
	    public MQVUserKeyingMaterial(IEncodable encodable) : base(encodable, info) {}
    
	    // конструктор при закодировании
	    public MQVUserKeyingMaterial(ISO.AlgorithmIdentifier ephemeralPublicKey, OctetString addedukm) 
		    : base(info, ephemeralPublicKey, addedukm) {}

	    public ISO.AlgorithmIdentifier EphemeralPublicKey { get { return (ISO.AlgorithmIdentifier)this[0]; }} 
	    public OctetString             AddedUkm           { get { return (OctetString            )this[1]; }}
    }
}
