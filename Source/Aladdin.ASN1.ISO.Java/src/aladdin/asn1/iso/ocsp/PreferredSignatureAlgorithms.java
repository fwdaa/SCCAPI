package aladdin.asn1.iso.ocsp;
import aladdin.asn1.*;
import java.io.*;

// PreferredSignatureAlgorithms ::= SEQUENCE OF PreferredSignatureAlgorithm

public final class PreferredSignatureAlgorithms extends Sequence<PreferredSignatureAlgorithm>
{
	// конструктор при раскодировании
	public PreferredSignatureAlgorithms(IEncodable encodable) throws IOException 
	{
		super(encodable);
	}
	// конструктор при закодировании
	public PreferredSignatureAlgorithms(PreferredSignatureAlgorithm... values) 
	{
		super(PreferredSignatureAlgorithm.class, values); 
	}
}
