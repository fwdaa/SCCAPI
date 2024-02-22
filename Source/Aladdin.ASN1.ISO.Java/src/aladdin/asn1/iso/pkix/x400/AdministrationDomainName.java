package aladdin.asn1.iso.pkix.x400;
import aladdin.asn1.*; 
import java.io.*;

//	AdministrationDomainName ::= [APPLICATION 2] EXPLICIT CHOICE {
//		numeric   NumericString   (SIZE (0..ub-domain-name-length)),
//		printable PrintableString (SIZE (0..ub-domain-name-length)) 
//	}
//	ub-domain-name-length INTEGER ::= 16

public final class AdministrationDomainName extends Explicit<IEncodable>
{
    private static final long serialVersionUID = 6617706551421678316L;
    
    // допустимые типы объекта
    public static boolean isValidTag(Tag tag) { return tag.equals(Tag.application(2)); }

    // информация о структуре
    private static final ObjectInfo[] info = new ObjectInfo[] { 

        new ObjectInfo(new ObjectCreator(NumericString  .class).factory(0, 16), Cast.N), 
		new ObjectInfo(new ObjectCreator(PrintableString.class).factory(0, 16), Cast.N), 
    }; 
    // конструктор при раскодировании
    public AdministrationDomainName(IEncodable encodable) throws IOException 
    { 
        super(new Choice(info), encodable); 
    } 
    // конструктор при закодировании
    public AdministrationDomainName(OctetString value) 
    { 
        super(new Choice(info), Tag.application(2), value); 
    }  
}
