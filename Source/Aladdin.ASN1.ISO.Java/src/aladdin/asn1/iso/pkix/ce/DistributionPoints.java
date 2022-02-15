package aladdin.asn1.iso.pkix.ce;
import aladdin.asn1.*; 
import java.io.*;

// CRLDistributionPoints ::= SEQUENCE OF DistributionPoint

public final class DistributionPoints extends Sequence<DistributionPoint>
{
	// конструктор при раскодировании
	public DistributionPoints(IEncodable encodable) throws IOException 
	{
		super(DistributionPoint.class, encodable); 
	}
	// конструктор при закодировании
	public DistributionPoints(DistributionPoint... values) 
	{
		super(DistributionPoint.class, values); 
	}
}
