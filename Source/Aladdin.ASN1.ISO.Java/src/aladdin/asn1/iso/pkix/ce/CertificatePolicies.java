package aladdin.asn1.iso.pkix.ce;
import aladdin.asn1.*; 
import java.io.*;

// CertificatePolicies ::= SEQUENCE OF PolicyInformation

public final class CertificatePolicies extends Sequence<PolicyInformation>
{
	// конструктор при раскодировании
	public CertificatePolicies(IEncodable encodable) throws IOException
	{
		super(PolicyInformation.class, encodable); 
	} 
	// конструктор при закодировании
	public CertificatePolicies(PolicyInformation... values) 
	{
		super(PolicyInformation.class, values); 
	}
	// найти требуемый атрибут
	public final PolicyInformation get(String oid)
	{
		// для всех атрибутов
		for (PolicyInformation information : this)
		{
			// проверить совпадение идентификатора
			if (information.policyIdentifier().value().equals(oid)) return information; 
		}
		return null; 
	}
}
