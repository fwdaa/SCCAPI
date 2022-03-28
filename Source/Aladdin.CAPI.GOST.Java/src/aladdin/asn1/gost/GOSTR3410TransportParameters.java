package aladdin.asn1.gost;
import aladdin.asn1.*; 
import aladdin.asn1.iso.pkix.*; 
import java.io.*; 

//	GOSTR3410TransportParameters ::= SEQUENCE {
//		encryptionParamSet				OBJECT IDENTIFIER,
//		ephemeralPublicKey [0] IMPLICIT SubjectPublicKeyInfo	OPTIONAL,
//		ukm								OCTET STRING ( SIZE(8) )
//	}

public final class GOSTR3410TransportParameters extends Sequence<IEncodable>
{
    private static final long serialVersionUID = 3866696569188681795L;
    
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

        new ObjectInfo(new ObjectCreator(ObjectIdentifier       .class).factory( ), Cast.N,	Tag.ANY			), 
		new ObjectInfo(new ObjectCreator(SubjectPublicKeyInfo   .class).factory( ), Cast.O,	Tag.context(0)	), 
		new ObjectInfo(new ObjectCreator(OctetString            .class).factory(8), Cast.N,	Tag.ANY			), 
	}; 
	// конструктор при раскодировании
	public GOSTR3410TransportParameters(IEncodable encodable) throws IOException { super(encodable, info); }
    
	// конструктор при закодировании
	public GOSTR3410TransportParameters(ObjectIdentifier encryptionParamSet, 
		SubjectPublicKeyInfo ephemeralPublicKey, OctetString ukm)
	{
        super(info, encryptionParamSet, ephemeralPublicKey, ukm); 
    }  
	public final ObjectIdentifier       encryptionParamSet() { return (ObjectIdentifier     )get(0); }
	public final SubjectPublicKeyInfo	ephemeralPublicKey() { return (SubjectPublicKeyInfo	)get(1); } 
	public final OctetString            ukm				  () { return (OctetString          )get(2); } 
}
