package aladdin.asn1.iso;
import aladdin.asn1.*; 
import java.io.*;

// CertificateSet ::= SET OF CertificateChoices

public final class CertificateSet extends Set<IEncodable>
{
	// конструктор при раскодировании
	public CertificateSet(IEncodable encodable) throws IOException 
	{
		super(new ChoiceCreator(CertificateChoices.class).factory(), encodable); 
	} 
	// конструктор при закодировании
	public CertificateSet(IEncodable... values) 
	{
		super(new ChoiceCreator(CertificateChoices.class).factory(), values); 	
	} 
}

