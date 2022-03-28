package aladdin.asn1.iso.pkix.ce;
import aladdin.asn1.*; 
import java.io.*; 

//	PolicyMappings ::= SEQUENCE OF PolicyMapping

public final class PolicyMappings extends Sequence<PolicyMapping>
{
    private static final long serialVersionUID = -3281204096475973506L;
    
	// конструктор при раскодировании
	public PolicyMappings(IEncodable encodable) throws IOException 
	{
		super(PolicyMapping.class, encodable); 
	}
	// конструктор при закодировании
	public PolicyMappings(PolicyMapping... values) 
	{
		super(PolicyMapping.class, values); 
	}
	// найти требуемый атрибут
	public final PolicyMapping get(String oid) 
	{
		// для всех атрибутов
		for (PolicyMapping mapping : this)
		{
			// проверить совпадение идентификатора
			if (mapping.issuerDomainPolicy().value().equals(oid)) return mapping; 
		}
		return null; 
	}
}
