package aladdin.asn1.iso.pkix.ce;
import aladdin.asn1.*; 
import java.io.*; 

//	NameConstraints ::= SEQUENCE {
//		permittedSubtrees [0] IMPLICIT GeneralSubtrees OPTIONAL,
//		excludedSubtrees  [1] IMPLICIT GeneralSubtrees OPTIONAL 
//	}

public final class NameConstraints extends Sequence<GeneralSubtrees>
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(GeneralSubtrees.class).factory(), Cast.O, Tag.context(0)), 
		new ObjectInfo(new ObjectCreator(GeneralSubtrees.class).factory(), Cast.O, Tag.context(1)), 
	}; 
	// конструктор при раскодировании
	public NameConstraints(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public NameConstraints(GeneralSubtrees permittedSubtrees, 
		GeneralSubtrees excludedSubtrees) 
	{
		super(info, permittedSubtrees, excludedSubtrees); 
	}
	public final GeneralSubtrees permittedSubtrees() { return get(0); } 
	public final GeneralSubtrees excludedSubtrees () { return get(1); }
}
