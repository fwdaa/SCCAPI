package aladdin.asn1.iso.pkix;
import aladdin.asn1.*; 
import java.io.*; 

// RevokedCertificates ::= SEQUENCE OF RevokedCertificate

public final class RevokedCertificates extends Sequence<RevokedCertificate>
{
    private static final long serialVersionUID = -5959341407700025141L;
    
	// конструктор при раскодировании
	public RevokedCertificates(IEncodable encodable) throws IOException 
	{
		super(RevokedCertificate.class, encodable); 
	} 
	// конструктор при закодировании
	public RevokedCertificates(RevokedCertificate... values) 
	{
		super(RevokedCertificate.class, values); 
	} 
}
