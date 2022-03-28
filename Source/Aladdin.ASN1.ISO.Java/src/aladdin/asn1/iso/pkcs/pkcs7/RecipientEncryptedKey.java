package aladdin.asn1.iso.pkcs.pkcs7;
import aladdin.asn1.*; 
import java.io.*; 

//	RecipientEncryptedKey ::= SEQUENCE {
//		rid				KeyAgreeRecipientIdentifier,
//		encryptedKey	OCTET STRING
//	}

public final class RecipientEncryptedKey extends Sequence<IEncodable>
{
    private static final long serialVersionUID = -7905552546133249862L;
    
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ChoiceCreator(KeyAgreeRecipientIdentifier.class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(OctetString				.class).factory(), Cast.N), 
	}; 
	// конструктор при раскодировании
	public RecipientEncryptedKey(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public RecipientEncryptedKey(IEncodable rid, OctetString encryptedKey) 
	{
		super(info, rid, encryptedKey); 
	}
	public final IEncodable     rid			() { return				  get(0); } 
	public final OctetString	encryptedKey() { return (OctetString )get(1); }
}
