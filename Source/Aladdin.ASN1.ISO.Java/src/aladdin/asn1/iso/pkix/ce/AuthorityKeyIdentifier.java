package aladdin.asn1.iso.pkix.ce;
import aladdin.asn1.*; 
import aladdin.asn1.Integer; 
import aladdin.asn1.iso.pkix.*; 
import java.io.*; 

//	AuthorityKeyIdentifier ::= SEQUENCE {
//		keyIdentifier             [0] IMPLICIT OCTET STRING	OPTIONAL,
//		authorityCertIssuer       [1] IMPLICIT GeneralNames OPTIONAL,
//		authorityCertSerialNumber [2] IMPLICIT INTEGER		OPTIONAL 
//	}

public final class AuthorityKeyIdentifier extends Sequence<IEncodable>
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(OctetString	.class).factory(), Cast.O, Tag.context(0)), 
		new ObjectInfo(new ObjectCreator(GeneralNames   .class).factory(), Cast.O, Tag.context(1)), 
		new ObjectInfo(new ObjectCreator(Integer        .class).factory(), Cast.O, Tag.context(2)), 
	}; 
	// конструктор при раскодировании
	public AuthorityKeyIdentifier(IEncodable encodable) throws IOException { super(encodable, info); 
	
		// проверить наличие элементов
		if (authorityCertIssuer() == null && authorityCertSerialNumber() != null) throw new IOException(); 
		if (authorityCertIssuer() != null && authorityCertSerialNumber() == null) throw new IOException(); 
	}
	// конструктор при закодировании
	public AuthorityKeyIdentifier(OctetString keyIdentifier, GeneralNames authorityCertIssuer, 
		Integer authorityCertSerialNumber) 
	{
		super(info, keyIdentifier, authorityCertIssuer, authorityCertSerialNumber); 
		
		// проверить наличие элементов
		if (authorityCertIssuer == null && authorityCertSerialNumber != null) throw new IllegalArgumentException(); 
		if (authorityCertIssuer != null && authorityCertSerialNumber == null) throw new IllegalArgumentException(); 
	}
	public final OctetString	keyIdentifier			 () { return (OctetString	)get(0); } 
	public final GeneralNames   authorityCertIssuer		 () { return (GeneralNames	)get(1); }
	public final Integer        authorityCertSerialNumber() { return (Integer       )get(2); }
}
