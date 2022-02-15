package aladdin.asn1.ansi.x962;
import aladdin.asn1.*; 
import java.io.*;

// ECPoints ::= SEQUENCE OF ECPoint

public final class ECPoints extends Sequence<OctetString>
{
	// конструктор при раскодировании
	public ECPoints(IEncodable encodable) throws IOException 
	{
		super(OctetString.class, encodable); 
	} 
	// конструктор при закодировании
	public ECPoints(OctetString... values) 
	{
		super(OctetString.class, values); 
	} 
}
