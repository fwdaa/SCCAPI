package aladdin.asn1.iso;
import aladdin.asn1.*; 
import java.io.*; 

//	OtherCertificateFormat ::= SEQUENCE {
//		otherCertFormat OBJECT IDENTIFIER,
//		otherCert ANY DEFINED BY otherCertFormat 
//	}

public final class OtherCertificateFormat extends Sequence<IEncodable>
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(ObjectIdentifier.class).factory(), Cast.N), 
		new ObjectInfo(    ImplicitCreator						.factory  , Cast.N), 
	}; 
	// конструктор при раскодировании
	public OtherCertificateFormat(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public OtherCertificateFormat(ObjectIdentifier otherCertFormat, IEncodable otherCert) 
	{
		super(info, otherCertFormat, otherCert); 
	}
	public final ObjectIdentifier otherCertFormat	() { return (ObjectIdentifier)get(0); } 
	public final IEncodable		  otherCert         () { return                   get(1); }
}