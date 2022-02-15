package aladdin.asn1.iso.pkix;
import aladdin.asn1.*; 
import java.io.*; 

// RelativeDistinguishedNames ::= SEQUENCE OF RelativeDistinguishedName

public final class RelativeDistinguishedNames extends Sequence<RelativeDistinguishedName>
{
	// конструктор при раскодировании
	public RelativeDistinguishedNames(IEncodable encodable) throws IOException
	{
		super(RelativeDistinguishedName.class, encodable); 
	}
	// конструктор при закодировании
	public RelativeDistinguishedNames(RelativeDistinguishedName... values) 
	{
		super(RelativeDistinguishedName.class, values);
	}
}
