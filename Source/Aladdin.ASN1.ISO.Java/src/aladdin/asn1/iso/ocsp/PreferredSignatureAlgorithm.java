package aladdin.asn1.iso.ocsp;
import aladdin.asn1.*;
import aladdin.asn1.iso.*;
import java.io.*;

// PreferredSignatureAlgorithm ::= SEQUENCE {
//    sigIdentifier  AlgorithmIdentifier{SIGNATURE-ALGORITHM, {...}},
//    certIdentifier AlgorithmIdentifier{PUBLIC-KEY, {...}} OPTIONAL
// }

public class PreferredSignatureAlgorithm extends Sequence<IEncodable>
{
    private static final long serialVersionUID = 4422999841875621444L;

    // информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(AlgorithmIdentifier.class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(AlgorithmIdentifier.class).factory(), Cast.N), 
	}; 
	// конструктор при раскодировании
	public PreferredSignatureAlgorithm(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public PreferredSignatureAlgorithm(AlgorithmIdentifier sigIdentifier, AlgorithmIdentifier certIdentifier) 
	{ 
		super(info, sigIdentifier, certIdentifier); 
	}
	public final AlgorithmIdentifier  sigIdentifier () { return (AlgorithmIdentifier)get(0); } 
	public final AlgorithmIdentifier  certIdentifier() { return (AlgorithmIdentifier)get(1); }
}
