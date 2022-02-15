package aladdin.asn1.iso.pkix.ce;
import aladdin.asn1.*; 
import java.io.*;

// GeneralSubtrees ::= SEQUENCE OF GeneralSubtree

public final class GeneralSubtrees extends Sequence<GeneralSubtree>
{
	// конструктор при раскодировании
	public GeneralSubtrees(IEncodable encodable) throws IOException 
	{
		super(GeneralSubtree.class, encodable); 
	}
	// конструктор при закодировании
	public GeneralSubtrees(GeneralSubtree... values) 
	{
		super(GeneralSubtree.class, values); 
	}
}
