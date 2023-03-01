package aladdin.asn1.iso.ocsp;
import aladdin.asn1.*;
import aladdin.asn1.iso.*;
import aladdin.asn1.iso.pkix.*;
import java.io.*;

// BasicOCSPResponse ::= SEQUENCE {
//		tbsResponseData         ResponseData,
//		signatureAlgorithm      AlgorithmIdentifier {SIGNATURE-ALGORITHM, {sa-dsaWithSHA1 | sa-rsaWithSHA1 | sa-rsaWithMD5 | sa-rsaWithMD2, ...}},
//		signature               BIT STRING,
//		certs				[0] EXPLICIT SEQUENCE OF Certificate OPTIONAL
// }

public class BasicOCSPResponse extends Sequence<IEncodable>
{
    private static final long serialVersionUID = -8338637218368601837L;

    // информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator  (ResponseData       .class).factory(), Cast.N                 ), 
		new ObjectInfo(new ObjectCreator  (AlgorithmIdentifier.class).factory(), Cast.N                 ), 
		new ObjectInfo(new ObjectCreator  (BitString          .class).factory(), Cast.N                 ), 
		new ObjectInfo(new SequenceCreator(Certificate        .class).factory(), Cast.EO, Tag.context(0)), 
	}; 
	// конструктор при раскодировании
	public BasicOCSPResponse(IEncodable encodable) throws IOException { super(encodable, info); }
    
	// конструктор при закодировании
	public BasicOCSPResponse(ResponseData tbsResponseData, AlgorithmIdentifier signatureAlgorithm, 
        BitString signature, Sequence<Certificate> certs) 
	{ 
		super(info, tbsResponseData, signatureAlgorithm, signature, certs); 
	}
	public final ResponseData           tbsResponseData   () { return (ResponseData         )get(0); } 
	public final AlgorithmIdentifier    signatureAlgorithm() { return (AlgorithmIdentifier  )get(1); }
	public final BitString              signature         () { return (BitString            )get(2); }
    @SuppressWarnings({"unchecked"}) 
	public final Sequence<Certificate>  certs             () { return (Sequence<Certificate>)get(3); }
}
