package aladdin.asn1.iso.pkcs.pkcs12;
import aladdin.asn1.*; 
import java.io.*;

//	CertBag ::= SEQUENCE {
//		certId						OBJECT IDENTIFIER,
//		certValue	[0] EXPLICIT	ANY DEFINED BY certId
//	}

public final class CertBag extends Sequence<IEncodable>
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(ObjectIdentifier.class).factory(), Cast.N,	Tag.ANY			), 
		new ObjectInfo(    ImplicitCreator						.factory  , Cast.E,	Tag.context(0)	), 
	}; 
	// конструктор при раскодировании
	public CertBag(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public CertBag(ObjectIdentifier certId, IEncodable certValue) 
	{
		super(info, certId, certValue); 
	}
	public final ObjectIdentifier certId	() { return (ObjectIdentifier)get(0); } 
	public final IEncodable		  certValue () { return                   get(1); }
}
