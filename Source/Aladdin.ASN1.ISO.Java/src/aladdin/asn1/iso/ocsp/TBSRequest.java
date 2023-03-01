package aladdin.asn1.iso.ocsp;
import aladdin.asn1.*;
import aladdin.asn1.iso.pkix.*;
import java.io.*;

// TBSRequest ::= SEQUENCE {
//     version           [0] EXPLICIT INTEGER DEFAULT v1(0),
//     requestorName     [1] EXPLICIT GeneralName OPTIONAL,
//     requestList           SEQUENCE OF Request,
//     requestExtensions [2] EXPLICIT Extensions {{re-ocsp-nonce | re-ocsp-response, ..., re-ocsp-preferred-signature-algorithms}} OPTIONAL
//  }

public class TBSRequest extends Sequence<IEncodable>
{
    private static final long serialVersionUID = -1265760254928827535L;

    // информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator  (aladdin.asn1.Integer.class).factory(), Cast.E , Tag.context(0), new aladdin.asn1.Integer(0)), 
		new ObjectInfo(new ChoiceCreator  (GeneralName         .class).factory(), Cast.EO, Tag.context(1)                             ), 
		new ObjectInfo(new SequenceCreator(Request             .class).factory(), Cast.N                                              ), 
		new ObjectInfo(new ObjectCreator  (Extensions          .class).factory(), Cast.EO, Tag.context(2)                             ) 
	}; 
	// конструктор при раскодировании
	public TBSRequest(IEncodable encodable) throws IOException { super(encodable, info); }
    
	// конструктор при закодировании
	public TBSRequest(aladdin.asn1.Integer version, IEncodable requestorName, 
        Sequence<Request> requestList, Extensions requestExtensions) 
	{ 
		super(info, version, requestorName, requestList, requestExtensions); 
	}
	public final aladdin.asn1.Integer version           () { return (aladdin.asn1.Integer)get(0); } 
	public final IEncodable           requestorName     () { return                       get(1); }
    @SuppressWarnings({"unchecked"}) 
	public final Sequence<Request>    requestList       () { return (Sequence<Request>   )get(2); }
	public final Extensions           requestExtensions () { return (Extensions          )get(2); }
}
