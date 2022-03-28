package aladdin.asn1.iso.pkcs.pkcs6;
import aladdin.asn1.*; 
import aladdin.asn1.Integer; 
import aladdin.asn1.iso.*; 
import aladdin.asn1.iso.pkix.*; 
import java.io.*;

//	ExtendedCertificateInfo ::= SEQUENCE {
//		version		INTEGER,
//		certificate Certificate,
//		attributes	Attributes 
//	}

public final class ExtendedCertificateInfo extends Sequence<IEncodable>
{
    private static final long serialVersionUID = 5894748203188419219L;
    
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(Integer	.class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(Certificate.class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(Attributes	.class).factory(), Cast.N), 
	}; 
	// конструктор при раскодировании
	public ExtendedCertificateInfo(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public ExtendedCertificateInfo(Integer version, 
		Certificate certificate, Attributes attributes) 
	{
		super(info, version, certificate, attributes); 
	}
	public final Integer        version		() { return (Integer	)get(0); } 
	public final Certificate	certificate	() { return (Certificate)get(1); }
	public final Attributes     attributes	() { return (Attributes	)get(2); }
}
