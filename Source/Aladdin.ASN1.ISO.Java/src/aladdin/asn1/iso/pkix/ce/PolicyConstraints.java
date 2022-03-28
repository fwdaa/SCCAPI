package aladdin.asn1.iso.pkix.ce;
import aladdin.asn1.*; 
import aladdin.asn1.Integer; 
import java.io.*; 

//	PolicyConstraints ::= SEQUENCE {
//		requireExplicitPolicy   [0] IMPLICIT INTEGER OPTIONAL,
//		inhibitPolicyMapping    [1] IMPLICIT INTEGER OPTIONAL 
//	}

public final class PolicyConstraints extends Sequence<Integer>
{
    private static final long serialVersionUID = 309708274525591622L;
    
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(Integer.class).factory(0), Cast.O, Tag.context(0)), 
		new ObjectInfo(new ObjectCreator(Integer.class).factory(0), Cast.O, Tag.context(1)), 
	}; 
	// конструктор при раскодировании
	public PolicyConstraints(IEncodable encodable) throws IOException { super(encodable, info); }
	
	// конструктор при закодировании
	public PolicyConstraints(Integer requireExplicitPolicy, 
		Integer inhibitPolicyMapping) 
	{
		super(info, requireExplicitPolicy, inhibitPolicyMapping); 
	}
	public final Integer requireExplicitPolicy() { return get(0); } 
	public final Integer inhibitPolicyMapping () { return get(1); }
}
