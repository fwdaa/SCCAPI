package aladdin.asn1.iso.pkix;
import aladdin.asn1.*; 
import java.io.*;

//	AttributeValidity  ::= SEQUENCE {
//		notBeforeTime  GeneralizedTime,
//		notAfterTime   GeneralizedTime
//	}

public final class AttributeValidity extends Sequence<GeneralizedTime>
{
    private static final long serialVersionUID = 6669920512900335813L;
    
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(GeneralizedTime.class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(GeneralizedTime.class).factory(), Cast.N), 
	}; 
	// конструктор при раскодировании
	public AttributeValidity(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public AttributeValidity(GeneralizedTime notBeforeTime, 
		GeneralizedTime notAfterTime) 
	{
		super(info, notBeforeTime, notAfterTime); 
	}
	public final GeneralizedTime notBeforeTime() { return get(0); } 
	public final GeneralizedTime notAfterTime () { return get(1); }
}
