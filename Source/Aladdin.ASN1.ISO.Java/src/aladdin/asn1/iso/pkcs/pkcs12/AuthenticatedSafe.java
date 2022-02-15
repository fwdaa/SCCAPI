package aladdin.asn1.iso.pkcs.pkcs12;
import aladdin.asn1.*; 
import aladdin.asn1.iso.pkcs.*; 
import java.io.*;

// AuthenticatedSafe ::= SEQUENCE OF ContentInfo

public final class AuthenticatedSafe extends Sequence<ContentInfo>
{
	// конструктор при раскодировании
	public AuthenticatedSafe(IEncodable encodable) throws IOException
	{
		super(ContentInfo.class, encodable); 
	} 
	// конструктор при закодировании
	public AuthenticatedSafe(ContentInfo... values) 
	{
		super(ContentInfo.class, values); 
	} 
}
