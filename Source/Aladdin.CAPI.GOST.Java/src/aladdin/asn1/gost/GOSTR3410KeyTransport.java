package aladdin.asn1.gost;
import aladdin.asn1.*; 
import java.io.*; 

//	KeyTransport ::= SEQUENCE {
//		sessionEncryptedKey					GOST28147EncryptedKey,
//		transportParameters [0] IMPLICIT	GOSTR3410TransportParameters OPTIONAL
//	}

public final class GOSTR3410KeyTransport extends Sequence<IEncodable>
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

        new ObjectInfo(new ObjectCreator(EncryptedKey                .class).factory(), Cast.N,	Tag.ANY			), 
		new ObjectInfo(new ObjectCreator(GOSTR3410TransportParameters.class).factory(), Cast.O,	Tag.context(0)	), 
	}; 
	// конструктор при раскодировании
	public GOSTR3410KeyTransport(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public GOSTR3410KeyTransport(EncryptedKey sessionEncryptedKey, 
		GOSTR3410TransportParameters transportParameters) 
    {
        super(info, sessionEncryptedKey, transportParameters); 
    }
	public final EncryptedKey			      sessionEncryptedKey() { return (EncryptedKey		          )get(0); }
	public final GOSTR3410TransportParameters transportParameters() { return (GOSTR3410TransportParameters)get(1); } 
}
