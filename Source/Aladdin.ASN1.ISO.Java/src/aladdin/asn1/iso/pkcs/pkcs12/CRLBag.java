package aladdin.asn1.iso.pkcs.pkcs12;
import aladdin.asn1.*; 
import java.io.*;

//	CRLBag ::= SEQUENCE {
//		crlId			         OBJECT IDENTIFIER,
//		crltValue	[0] EXPLICIT ANY DEFINED BY crlId
//	}

public final class CRLBag extends Sequence<IEncodable>
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(ObjectIdentifier.class).factory(), Cast.N,	Tag.ANY			), 
		new ObjectInfo(    ImplicitCreator					    .factory  , Cast.E,	Tag.context(0)	), 
	}; 
	// конструктор при раскодировании
	public CRLBag(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public CRLBag(ObjectIdentifier crlId, IEncodable crltValue) 
	{
		super(info, crlId, crltValue); 
	}
	public final ObjectIdentifier	crlId	 () { return (ObjectIdentifier)get(0); } 
	public final IEncodable         crltValue() { return	 			   get(1); }
}
