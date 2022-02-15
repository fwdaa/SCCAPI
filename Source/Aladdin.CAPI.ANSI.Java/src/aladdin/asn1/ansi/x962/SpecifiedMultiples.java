package aladdin.asn1.ansi.x962;
import aladdin.asn1.*; 
import java.io.*;

////////////////////////////////////////////////////////////////////////////////
// SpecifiedMultiples ::= SEQUENCE OF SpecifiedMultiple
////////////////////////////////////////////////////////////////////////////////
public final class SpecifiedMultiples extends Sequence<SpecifiedMultiple>
{
	// конструктор при раскодировании
	public SpecifiedMultiples(IEncodable encodable) throws IOException 
	{
		super(SpecifiedMultiple.class, encodable); 
	} 
	// конструктор при закодировании
	public SpecifiedMultiples(SpecifiedMultiple... values) 
	{
		super(SpecifiedMultiple.class, values); 
	} 
}
