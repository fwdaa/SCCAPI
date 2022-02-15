package aladdin.asn1.iso.pkcs.pkcs1;
import aladdin.asn1.*; 
import java.io.*; 

// OtherPrimeInfos ::= SEQUENCE OF OtherPrimeInfo

public final class OtherPrimeInfos extends Sequence<OtherPrimeInfo>
{
	// конструктор при раскодировании
	public OtherPrimeInfos(IEncodable encodable) throws IOException
	{
		super(OtherPrimeInfo.class, encodable); 
	}
	// конструктор при закодировании
	public OtherPrimeInfos(OtherPrimeInfo... values) 
	{
		super(OtherPrimeInfo.class, values);
	}
}
