package aladdin.asn1.iso.ocsp;
import aladdin.asn1.*;
import java.io.*;

// PreferredSignatureAlgorithms ::= SEQUENCE OF PreferredSignatureAlgorithm

public final class PreferredSignatureAlgorithms extends Sequence<PreferredSignatureAlgorithm>
{
    private static final long serialVersionUID = 7045176381862602231L;

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
