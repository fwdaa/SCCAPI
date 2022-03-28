package aladdin.asn1.iso.pkcs.pkcs12;
import aladdin.asn1.*; 
import aladdin.asn1.Integer; 
import aladdin.asn1.iso.pkcs.*; 
import aladdin.asn1.iso.pkcs.pkcs7.*; 
import java.io.*; 

//	PFX ::= SEQUENCE {
//		version		INTEGER {v3(3)}(v3,...),
//		authSafe	ContentInfo,
//		macData		MacData			OPTIONAL
//	}

public final class PFX extends Sequence<IEncodable>
{
    private static final long serialVersionUID = -7332540143450477096L;
    
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(Integer	.class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(ContentInfo.class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(MacData	.class).factory(), Cast.O), 
	}; 
	// конструктор при раскодировании
	public PFX(IEncodable encodable) throws IOException { super(encodable, info); }
	
	// конструктор при закодировании
	public PFX(Integer version, ContentInfo authSafe, MacData macData) 
	{
		super(info, version, authSafe, macData); 
	}
	public final Integer        version	() { return (Integer	)get(0); } 
	public final ContentInfo	authSafe() { return (ContentInfo)get(1); }
	public final MacData		macData	() { return (MacData	)get(2); }

	public final AuthenticatedSafe getAuthSafeContent() throws IOException
	{ 
		// проверить явное указание данных
		if (authSafe().contentType().value().equals(aladdin.asn1.iso.pkcs.pkcs7.OID.DATA)) 
		{
			// получить содержимое контейнера
			byte[] encoded = (new OctetString(authSafe().inner())).value(); 

			// вернуть содержимое контейнера
			return new AuthenticatedSafe(Encodable.decode(encoded)); 
		}
		else {
			SignedData signedData = new SignedData(authSafe().inner()); 
			
			// получить содержимое контейнера
			byte[] encoded = signedData.encapContentInfo().eContent().value(); 

			// вернуть содержимое контейнера
			return new AuthenticatedSafe(Encodable.decode(encoded)); 
		}
	}
}
