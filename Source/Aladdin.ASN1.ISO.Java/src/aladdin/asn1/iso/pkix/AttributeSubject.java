package aladdin.asn1.iso.pkix;
import aladdin.asn1.*; 
import java.io.*;

//	AttributeSubject ::= SEQUENCE {
//		baseCertificateID   [0] IMPLICIT IssuerSerial OPTIONAL,
//		entityName          [1] IMPLICIT GeneralNames OPTIONAL,
//		objectDigestInfo    [2] IMPLICIT ObjectDigestInfo OPTIONAL
//	}

public final class AttributeSubject extends Sequence<IEncodable>
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(IssuerSerial		.class).factory(), Cast.O, Tag.context(0)), 
		new ObjectInfo(new ObjectCreator(GeneralNames		.class).factory(), Cast.O, Tag.context(1)), 
		new ObjectInfo(new ObjectCreator(ObjectDigestInfo	.class).factory(), Cast.O, Tag.context(2)), 
	}; 
	// конструктор при раскодировании
	public AttributeSubject(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public AttributeSubject(IssuerSerial baseCertificateID, 
		GeneralNames entityName, ObjectDigestInfo objectDigestInfo) 
	{
		super(info, baseCertificateID, entityName, objectDigestInfo); 
	}
	public final IssuerSerial		baseCertificateID() { return (IssuerSerial	  )get(0); } 
	public final GeneralNames		entityName		 () { return (GeneralNames	  )get(1); }
	public final ObjectDigestInfo	objectDigestInfo () { return (ObjectDigestInfo)get(2); }
}
