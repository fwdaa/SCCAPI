package aladdin.asn1.iso.pkix;
import aladdin.asn1.*; 
import aladdin.asn1.iso.*; 
import java.io.*; 

//	SubjectPublicKeyInfo  ::=  SEQUENCE  {
//		algorithm            AlgorithmIdentifier,
//		subjectPublicKey     BIT STRING  
//	}

public final class SubjectPublicKeyInfo extends Sequence<IEncodable>
{
    private static final long serialVersionUID = -466713104296888287L;
    
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(AlgorithmIdentifier.class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(BitString          .class).factory(), Cast.N), 
	}; 
	// конструктор при раскодировании
	public SubjectPublicKeyInfo(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public SubjectPublicKeyInfo(AlgorithmIdentifier algorithm, 
		BitString subjectPublicKey) 
	{
		super(info, algorithm, subjectPublicKey); 
	}
	public final AlgorithmIdentifier    algorithm	    () { return (AlgorithmIdentifier)get(0); } 
	public final BitString              subjectPublicKey() { return (BitString          )get(1); }
}
