package aladdin.asn1.iso.pkix;

import aladdin.asn1.*; 
import java.io.*;

//	AttrributeGeneralNames ::= SEQUENCE {
//		issuerName						GeneralNames		OPTIONAL,
//		baseCertificateID [0] IMPLICIT	IssuerSerial		OPTIONAL,
//		objectDigestInfo  [1] IMPLICIT	ObjectDigestInfo	OPTIONAL
//}

public final class AttributeGeneralNames extends Sequence<IEncodable>
{
    private static final long serialVersionUID = -8675581610622444090L;
    
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(GeneralNames    .class).factory(), Cast.O,	Tag.ANY			), 
		new ObjectInfo(new ObjectCreator(IssuerSerial    .class).factory(), Cast.O,	Tag.context(0)	), 
		new ObjectInfo(new ObjectCreator(ObjectDigestInfo.class).factory(), Cast.O,	Tag.context(1)	), 
	}; 
	// конструктор при раскодировании
	public AttributeGeneralNames(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public AttributeGeneralNames(GeneralNames issuerName, 
		IssuerSerial baseCertificateID, ObjectDigestInfo objectDigestInfo) 
	{
		super(info, issuerName, baseCertificateID, objectDigestInfo); 
	}
	public final GeneralNames		issuerName		 () { return (GeneralNames	  )get(0); }
	public final IssuerSerial		baseCertificateID() { return (IssuerSerial	  )get(1); } 
	public final ObjectDigestInfo	objectDigestInfo () { return (ObjectDigestInfo)get(2); }
}
