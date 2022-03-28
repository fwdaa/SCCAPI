package aladdin.asn1.gost;
import aladdin.asn1.*; 
import java.io.*; 

//	KeyTransferContent ::= SEQUENCE {
//		seanceVector			OCTET STRING (8),
//		encryptedPrivateKey 	GOST28147EncryptedKey, 
//		privateKeyParameters	[0] IMPLICIT GOSTPrivateKeyParameters OPTIONAL, 
//	}

public final class CryptoProKeyTransferContent extends Sequence<IEncodable>
{
    private static final long serialVersionUID = -5027605427350127643L;
    
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(OctetString		           .class).factory(), Cast.N,	Tag.ANY			), 
		new ObjectInfo(new ObjectCreator(EncryptedKey                  .class).factory(), Cast.N,	Tag.ANY			), 
		new ObjectInfo(new ObjectCreator(CryptoProPrivateKeyParameters .class).factory(), Cast.O,	Tag.context(0)	), 
	}; 
	// конструктор при раскодировании
	public CryptoProKeyTransferContent(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public CryptoProKeyTransferContent(OctetString seanceVector, EncryptedKey encryptedPrivateKey, 
		CryptoProPrivateKeyParameters privateKeyParameters)  
    {
        super(info, seanceVector, encryptedPrivateKey, privateKeyParameters); 
    }
	public final OctetString                    seanceVector		() { return (OctetString                    )get(0); }
	public final EncryptedKey			        encryptedPrivateKey	() { return (EncryptedKey                   )get(1); }
	public final CryptoProPrivateKeyParameters	privateKeyParameters() { return (CryptoProPrivateKeyParameters  )get(2); }
}
