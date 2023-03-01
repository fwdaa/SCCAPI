package aladdin.asn1.iso.ocsp;
import aladdin.asn1.*;
import java.io.*;

// CrlID ::= SEQUENCE {
//		crlUrl  [0] EXPLICIT IA5String OPTIONAL,
//		crlNum  [1] EXPLICIT INTEGER OPTIONAL,
//		crlTime [2] EXPLICIT GeneralizedTime OPTIONAL
// }

public class CrlID extends Sequence<IEncodable>
{
    private static final long serialVersionUID = -822429042839216730L;

    // информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(IA5String              .class).factory(), Cast.EO, Tag.context(0)), 
		new ObjectInfo(new ObjectCreator(aladdin.asn1.Integer   .class).factory(), Cast.EO, Tag.context(1)), 
		new ObjectInfo(new ObjectCreator(GeneralizedTime        .class).factory(), Cast.EO, Tag.context(2)) 
	}; 
	// конструктор при раскодировании
	public CrlID(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public CrlID(IA5String crlUrl, aladdin.asn1.Integer crlNum, GeneralizedTime crlTime) 
	{ 
		super(info, crlUrl, crlNum, crlTime); 
	}
	public final IA5String              crlUrl () { return (IA5String            )get(0); } 
	public final aladdin.asn1.Integer   crlNum () { return (aladdin.asn1.Integer )get(1); }
	public final GeneralizedTime        crlTime() { return (GeneralizedTime      )get(2); }
}
