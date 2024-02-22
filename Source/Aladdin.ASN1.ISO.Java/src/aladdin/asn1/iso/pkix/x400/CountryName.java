package aladdin.asn1.iso.pkix.x400;
import aladdin.asn1.*; 
import java.io.*;

// CountryName ::= [APPLICATION 1] EXPLICIT CHOICE {
//	x121-dcc-code		NumericString	(SIZE (ub-country-name-numeric-length)),
//	iso-3166-alpha2-code	PrintableString	(SIZE (ub-country-name-alpha-length)) 
// }
// ub-country-name-numeric-length	INTEGER ::= 3
// ub-country-name-alpha-length		INTEGER ::= 2

public final class CountryName extends Explicit<IEncodable>
{
    private static final long serialVersionUID = -2153097679986556332L;
    
    // допустимые типы объекта
    public static boolean isValidTag(Tag tag) { return tag.equals(Tag.application(1)); }

    // информация о структуре
    private static final ObjectInfo[] info = new ObjectInfo[] { 

        new ObjectInfo(new ObjectCreator(NumericString  .class).factory(3, 3), Cast.N), 
		new ObjectInfo(new ObjectCreator(PrintableString.class).factory(2, 2), Cast.N), 
    }; 
    // конструктор при раскодировании
    public CountryName(IEncodable encodable) throws IOException 
    { 
        super(new Choice(info), encodable); 
    } 
    // конструктор при закодировании
    public CountryName(OctetString value) 
    { 
        super(new Choice(info), Tag.application(1), value); 
    }  
}
