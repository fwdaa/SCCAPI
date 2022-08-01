package aladdin.asn1.iso.ocsp;
import aladdin.asn1.*;
import aladdin.asn1.iso.*;
import aladdin.asn1.iso.pkix.*;
import java.io.*;

// Signature ::= SEQUENCE {
//    signatureAlgorithm AlgorithmIdentifier { SIGNATURE-ALGORITHM, {...}},
//    signature          BIT STRING,
//    certs              [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL
// }

public class Signature extends Sequence<IEncodable>
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator  (AlgorithmIdentifier.class).factory(), Cast.N                 ), 
		new ObjectInfo(new ObjectCreator  (BitString          .class).factory(), Cast.N                 ), 
		new ObjectInfo(new SequenceCreator(Certificate        .class).factory(), Cast.EO, Tag.context(0)), 
	}; 
	// конструктор при раскодировании
	public Signature(IEncodable encodable) throws IOException { super(encodable, info); }
    
	// конструктор при закодировании
	public Signature(AlgorithmIdentifier signatureAlgorithm, BitString signature, Sequence<Certificate> certs) 
	{ 
		super(info, signatureAlgorithm, signature, certs); 
	}
	public final AlgorithmIdentifier    signatureAlgorithm  () { return (AlgorithmIdentifier    )get(0); } 
	public final BitString              signature           () { return (BitString              )get(1); }
	public final Sequence<Certificate>  certs               () { return (Sequence<Certificate>  )get(2); }
}
