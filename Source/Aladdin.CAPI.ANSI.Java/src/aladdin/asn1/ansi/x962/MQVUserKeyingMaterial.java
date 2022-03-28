package aladdin.asn1.ansi.x962;
import aladdin.asn1.*;
import aladdin.asn1.iso.*;
import java.io.*;

////////////////////////////////////////////////////////////////////////////////
// MQVUserKeyingMaterial ::= SEQUENCE {
//         ephemeralPublicKey OriginatorPublicKey,
//         addedukm [0] EXPLICIT UserKeyingMaterial OPTIONAL  
// }
////////////////////////////////////////////////////////////////////////////////
public final class MQVUserKeyingMaterial extends Sequence<IEncodable>
{
    private static final long serialVersionUID = -2509165690424500980L;
    
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(AlgorithmIdentifier.class).factory(), Cast.N , Tag.ANY       ), 
		new ObjectInfo(new ObjectCreator(OctetString        .class).factory(), Cast.EO, Tag.context(0)) 
	};
	// конструктор при раскодировании
	public MQVUserKeyingMaterial(IEncodable encodable) throws IOException { super(encodable, info); }
    
	// конструктор при закодировании
	public MQVUserKeyingMaterial(AlgorithmIdentifier ephemeralPublicKey, OctetString addedukm) 
	{
		super(info, ephemeralPublicKey, addedukm); 
	}
	public final AlgorithmIdentifier ephemeralPublicKey () { return (AlgorithmIdentifier)get(0); } 
	public final OctetString         addedukm           () { return (OctetString        )get(1); }
}
