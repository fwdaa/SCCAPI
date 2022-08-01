package aladdin.asn1.iso.ocsp;
import aladdin.asn1.*;
import aladdin.asn1.iso.*;
import java.io.*;

// CertID ::= SEQUENCE {
//     hashAlgorithm  AlgorithmIdentifier {DIGEST-ALGORITHM, {...}},
//     issuerNameHash OCTET STRING, 
//     issuerKeyHash  OCTET STRING, 
//     serialNumber   INTEGER
// }

public class CertID extends Sequence<IEncodable>
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(AlgorithmIdentifier .class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(OctetString         .class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(OctetString         .class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(aladdin.asn1.Integer.class).factory(), Cast.N), 
	}; 
	// конструктор при раскодировании
	public CertID(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public CertID(AlgorithmIdentifier hashAlgorithm, OctetString issuerNameHash, 
        OctetString issuerKeyHash, aladdin.asn1.Integer serialNumber) 
	{ 
		super(info, hashAlgorithm, issuerNameHash, issuerKeyHash, serialNumber); 
	}
	public final AlgorithmIdentifier    hashAlgorithm () { return (AlgorithmIdentifier  )get(0); } 
	public final OctetString            issuerNameHash() { return (OctetString          )get(1); }
	public final OctetString            issuerKeyHash () { return (OctetString          )get(2); }
	public final aladdin.asn1.Integer   serialNumber  () { return (aladdin.asn1.Integer )get(3); }
}
