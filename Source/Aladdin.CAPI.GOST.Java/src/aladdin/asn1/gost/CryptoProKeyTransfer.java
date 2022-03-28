package aladdin.asn1.gost;
import aladdin.asn1.*; 
import java.io.*; 

//	KeyTransfer ::= SEQUENCE {
//		keyTransferContent		KeyTransferContent,
//		macKeyTransferContent	OCTET STRING (4)
//	}

public final class CryptoProKeyTransfer extends Sequence<IEncodable>
{
    private static final long serialVersionUID = 7463159558106905253L;
    
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(CryptoProKeyTransferContent.class).factory(), Cast.N,	Tag.ANY), 
		new ObjectInfo(new ObjectCreator(OctetString                .class).factory(), Cast.N,	Tag.ANY), 
	}; 
	// конструктор при раскодировании
	public CryptoProKeyTransfer(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public CryptoProKeyTransfer(CryptoProKeyTransferContent keyTransferContent, OctetString macKeyTransferContent) 
    {
        super(info, keyTransferContent, macKeyTransferContent); 
    }
	public final CryptoProKeyTransferContent keyTransferContent   () { return (CryptoProKeyTransferContent)get(0); }
	public final OctetString                 macKeyTransferContent() { return (OctetString                )get(1); } 
}
