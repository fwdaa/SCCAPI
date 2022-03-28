package aladdin.asn1.iso.pkcs;
import aladdin.asn1.*; 
import java.io.*;

//	ContentInfo ::= SEQUENCE {
//		contentType				 OBJECT IDENTIFIER,
//		content		[0] EXPLICIT ANY DEFINED BY contentType 
//	}

public final class ContentInfo extends Sequence<IEncodable>
{
    private static final long serialVersionUID = -6967099234116925051L;
    
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(ObjectIdentifier.class).factory(), Cast.N,	Tag.ANY			), 
		new ObjectInfo(    ImplicitCreator						.factory  , Cast.E,	Tag.context(0)	), 
	}; 
	// конструктор при раскодировании
	public ContentInfo(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public ContentInfo(ObjectIdentifier contentType, IEncodable content) 
	{
		super(info, contentType, content); 
	}
	public final ObjectIdentifier contentType() { return (ObjectIdentifier)get(0); } 
	public final IEncodable		  inner	     () { return				   get(1); }
}
