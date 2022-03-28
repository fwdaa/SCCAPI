package aladdin.asn1.iso.pkcs.pkcs7;
import aladdin.asn1.*; 
import aladdin.asn1.iso.pkix.*; 
import java.io.*; 

// SignerInfos ::= SET OF SignerInfo

public final class SignerInfos extends Set<SignerInfo>
{
    private static final long serialVersionUID = 4892318201782154042L;
    
	// конструктор при раскодировании
	public SignerInfos(IEncodable encodable) throws IOException
	{
		super(SignerInfo.class, encodable); 
	}
	// конструктор при закодировании
	public SignerInfos(SignerInfo... values) 
	{
		super(SignerInfo.class, values); 
	}
	// найти информацию отдельного пользователя
	public final SignerInfo get(IssuerSerialNumber value)
	{
		// для всех подписавших лиц
		for (SignerInfo signerInfo : this)
		{
			// проверить совпадение типа
			if (!signerInfo.sid().tag().equals(Tag.SEQUENCE)) continue; 

			// проверить совпадение пользователей
			if (value.equals(signerInfo.sid())) return signerInfo; 
		}
		return null; 
	}
	// найти информацию отдельного пользователя
	public final SignerInfo get(OctetString value)
	{
		// для всех подписавших лиц
		for (SignerInfo signerInfo : this)
		{
			// проверить совпадение типа
			if (!signerInfo.sid().tag().equals(Tag.context(0))) continue; 

			// проверить совпадение пользователей
			if (value.equals(signerInfo.sid())) return signerInfo; 
		}
		return null; 
	}
}
