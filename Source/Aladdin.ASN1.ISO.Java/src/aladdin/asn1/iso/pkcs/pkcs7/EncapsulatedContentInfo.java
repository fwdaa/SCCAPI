package aladdin.asn1.iso.pkcs.pkcs7;
import aladdin.asn1.*; 
import java.io.*;

//	EncapsulatedContentInfo ::= SEQUENCE {
//		eContentType OBJECT IDENTIFIER,
//		eContent [0] EXPLICIT OCTET STRING OPTIONAL 
//	}

public final class EncapsulatedContentInfo extends Sequence<IEncodable>
{
    private static final long serialVersionUID = -581353768563607995L;
    
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(ObjectIdentifier	.class).factory(), Cast.N,	Tag.ANY			), 
		new ObjectInfo(new ObjectCreator(OctetString		.class).factory(), Cast.EO,	Tag.context(0)	), 
	}; 
	// конструктор при раскодировании
	public EncapsulatedContentInfo(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public EncapsulatedContentInfo(ObjectIdentifier eContentType, OctetString eContent) 
	{
		super(info, eContentType, eContent); 
	}
	public final ObjectIdentifier	eContentType() { return (ObjectIdentifier)get(0); } 
	public final OctetString		eContent	() { return (OctetString	 )get(1); }
}
