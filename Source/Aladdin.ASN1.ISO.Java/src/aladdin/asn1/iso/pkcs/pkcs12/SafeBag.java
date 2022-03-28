package aladdin.asn1.iso.pkcs.pkcs12;
import aladdin.asn1.*; 
import aladdin.asn1.iso.*; 
import java.io.*; 

//	SafeBag ::= SEQUENCE {
//		bagId						 OBJECT IDENTIFIER
//		bagValue		[0] EXPLICIT ANY DEFINED BY bagId,
//		bagAttributes				 Attributes				OPTIONAL
//	}

public final class SafeBag extends Sequence<IEncodable>
{
    private static final long serialVersionUID = 1109217028783528308L;
    
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(ObjectIdentifier   .class).factory(), Cast.N,	Tag.ANY			), 
		new ObjectInfo(    ImplicitCreator						   .factory  , Cast.E,	Tag.context(0)	), 
		new ObjectInfo(new ObjectCreator(Attributes         .class).factory(), Cast.O,	Tag.ANY			), 
	}; 
	// конструктор при раскодировании
	public SafeBag(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public SafeBag(ObjectIdentifier bagId, IEncodable bagValue, Attributes bagAttributes) 
	{
		super(info, bagId, bagValue, bagAttributes); 
	}
	public final ObjectIdentifier	bagId		 () { return (ObjectIdentifier	)get(0); } 
	public final IEncodable         bagValue	 () { return					 get(1); }
	public final Attributes         bagAttributes() { return (Attributes        )get(2); }
    
	///////////////////////////////////////////////////////////////////////
	// Идентификатор элемента
	///////////////////////////////////////////////////////////////////////
    public final byte[] localKeyID()
    {
        // извлечь атрибуты
		Attributes attributes = bagAttributes(); 

		// проверить наличие атрибутов
		if (attributes == null) return null; 

        // получить атрибут идентификатора
        Attribute attribute = attributes.get(aladdin.asn1.iso.pkcs.pkcs9.OID.LOCAL_KEY_ID);

        // проверить наличие атрибута
        if (attribute == null) return null; 

	    // указать идентификатор объекта
		try { return new OctetString(attribute.values().get(0)).value(); } 
        
        // обработать возможное исключение
        catch (IOException e) { return null; }
    }
}
