package aladdin.asn1.iso.pkix.ce;
import aladdin.asn1.*; 
import java.io.*; 

// PolicyQualifierInfos ::= SEQUENCE OF PolicyQualifierInfo

public final class PolicyQualifierInfos extends Sequence<PolicyQualifierInfo>
{
    private static final long serialVersionUID = 4710550668467799684L;
    
	// конструктор при раскодировании
	public PolicyQualifierInfos(IEncodable encodable) throws IOException 
	{ 
		super(PolicyQualifierInfo.class, encodable); 
	}
	// конструктор при закодировании
	public PolicyQualifierInfos(PolicyQualifierInfo... values) 
	{
		super(PolicyQualifierInfo.class, values); 
	}
	// найти требуемый атрибут
	public final PolicyQualifierInfo get(String oid)
	{
		// для всех атрибутов
		for (PolicyQualifierInfo info : this)
		{
			// проверить совпадение идентификатора
			if (info.policyQualifierId().value().equals(oid)) return info; 
		}
		return null; 
	}
}
