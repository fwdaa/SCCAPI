package aladdin.asn1.iso.pkix.ce;
import aladdin.asn1.*; 
import java.io.*; 

//	PrivateKeyUsagePeriod ::= SEQUENCE {
//		notBefore [0] IMPLICIT GeneralizedTime OPTIONAL,
//		notAfter  [1] IMPLICIT GeneralizedTime OPTIONAL 
//	}

public final class PrivateKeyUsagePeriod extends Sequence<GeneralizedTime>
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(GeneralizedTime.class).factory(), Cast.O, Tag.context(0)), 
		new ObjectInfo(new ObjectCreator(GeneralizedTime.class).factory(), Cast.O, Tag.context(1)), 
	}; 
	// конструктор при раскодировании
	public PrivateKeyUsagePeriod(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public PrivateKeyUsagePeriod(GeneralizedTime notBefore, 
		GeneralizedTime notAfter) 
	{
		super(info, notBefore, notAfter); 
	}
	public final GeneralizedTime notBefore() { return get(0); } 
	public final GeneralizedTime notAfter () { return get(1); }
}
