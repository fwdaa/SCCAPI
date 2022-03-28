package aladdin.asn1.iso.pkix.x400;
import aladdin.asn1.*; 
import java.io.*;

//	BuiltInDomainDefinedAttribute ::= SEQUENCE {
//		type  PrintableString (SIZE (1..ub-domain-defined-attribute-type-length)),
//		value PrintableString (SIZE (1..ub-domain-defined-attribute-value-length)) 
//	}
//	ub-domain-defined-attribute-type-length  INTEGER ::= 8
//	ub-domain-defined-attribute-value-length INTEGER ::= 128

public final class BuiltInDomainDefinedAttribute extends Sequence<PrintableString>
{
    private static final long serialVersionUID = 6841437510076698972L;
    
    // информация о структуре
    private static final ObjectInfo[] info = new ObjectInfo[] { 

        new ObjectInfo(new ObjectCreator(PrintableString.class).factory(1,   8), Cast.N), 
        new ObjectInfo(new ObjectCreator(PrintableString.class).factory(1, 128), Cast.N), 
    }; 
    // конструктор при раскодировании
    public BuiltInDomainDefinedAttribute(IEncodable encodable) throws IOException 
    {
        super(encodable, info); 
    } 
    // конструктор при закодировании
    public BuiltInDomainDefinedAttribute(PrintableString type, PrintableString value) 
    {
        super(info, type, value); 
    }
    public final PrintableString type () { return get(0); }
    public final PrintableString value() { return get(1); }
}
