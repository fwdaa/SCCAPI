package aladdin.asn1.iso.ocsp;
import aladdin.asn1.*;
import aladdin.asn1.iso.pkix.*;
import java.io.*;

// ResponseData ::= SEQUENCE {
//		version              [0] EXPLICIT INTEGER DEFAULT v1(0),
//      responderID				 ResponderID,
//      producedAt               GeneralizedTime,
//      responses                SEQUENCE OF SingleResponse,
//      responseExtensions   [1] EXPLICIT Extensions {{re-ocsp-nonce, ..., re-ocsp-extended-revoke}} OPTIONAL
// }

public class ResponseData extends Sequence<IEncodable>
{
    private static final long serialVersionUID = -1077038185093661697L;

    // информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator  (aladdin.asn1.Integer.class).factory(), Cast.E , Tag.context(0), new aladdin.asn1.Integer(0)), 
		new ObjectInfo(new ChoiceCreator  (ResponderID         .class).factory(), Cast.N                                              ), 
		new ObjectInfo(new ObjectCreator  (GeneralizedTime     .class).factory(), Cast.N                                              ), 
		new ObjectInfo(new SequenceCreator(SingleResponse      .class).factory(), Cast.N                                              ), 
		new ObjectInfo(new ObjectCreator  (Extensions          .class).factory(), Cast.EO, Tag.context(1)                             ) 
	}; 
	// конструктор при раскодировании
	public ResponseData(IEncodable encodable) throws IOException { super(encodable, info); }
    
	// конструктор при закодировании
	public ResponseData(aladdin.asn1.Integer version, IEncodable responderID, GeneralizedTime producedAt, 
        Sequence<SingleResponse> responses, Extensions responseExtensions) 
	{ 
		super(info, version, responderID, producedAt, responses, responseExtensions); 
	}
	public final aladdin.asn1.Integer       version             () { return (aladdin.asn1.Integer       )get(0); } 
	public final IEncodable                 responderID         () { return                              get(1); }
	public final GeneralizedTime            producedAt          () { return (GeneralizedTime            )get(2); }
    @SuppressWarnings({"unchecked"}) 
	public final Sequence<SingleResponse>   responses           () { return (Sequence<SingleResponse>   )get(3); }
	public final Extensions                 responseExtensions  () { return (Extensions                 )get(4); }
}
