package aladdin.asn1.iso.pkcs.pkcs9;
import aladdin.asn1.*; 
import java.io.*; 

// SMIMECapabilities ::= SEQUENCE OF SMIMECapability

public class SMIMECapabilities extends Sequence<SMIMECapability>
{
    private static final long serialVersionUID = 5361612941496122591L;
    
	// конструктор при раскодировании
	public SMIMECapabilities(IEncodable encodable) throws IOException
	{
		super(SMIMECapability.class, encodable); 
	} 
	// конструктор при закодировании
	public SMIMECapabilities(SMIMECapability... values) 
	{
		super(SMIMECapability.class, values); 
	} 
	// найти требуемый атрибут
	public final SMIMECapability get(String oid)
	{
		// для всех атрибутов
		for (SMIMECapability capability : this)
		{
			// проверить совпадение идентификатора
			if (capability.algorithm().value().equals(oid)) return capability; 
		}
		return null; 
	}
}
