package aladdin.asn1.iso.pkix;
import aladdin.asn1.*; 

//	DirectoryString ::= CHOICE {
//		teletexString       TeletexString   (SIZE (1..MAX)),
//		printableString     PrintableString (SIZE (1..MAX)),
//		universalString     UniversalString (SIZE (1..MAX)),
//		utf8String          UTF8String      (SIZE (1..MAX)),
//		bmpString           BMPString       (SIZE (1..MAX)) 
//	}

public final class DirectoryString extends Choice
{
	// информация о структуре
	private static ObjectInfo[] getInfo(int min, int max) 
	{ 
		return new ObjectInfo[] { 
			new ObjectInfo(new ObjectCreator(TeletexString  .class).factory(min, max), Cast.N), 
			new ObjectInfo(new ObjectCreator(PrintableString.class).factory(min, max), Cast.N), 
			new ObjectInfo(new ObjectCreator(UniversalString.class).factory(min, max), Cast.N), 
			new ObjectInfo(new ObjectCreator(UTF8String     .class).factory(min, max), Cast.N), 
			new ObjectInfo(new ObjectCreator(BMPString      .class).factory(min, max), Cast.N), 
		}; 
	} 
	// конструктор
	public DirectoryString(int min, int max) { super(getInfo(min, max)); } 

	// конструктор
	public DirectoryString(int min) { this(min, java.lang.Integer.MAX_VALUE); } 

	// конструктор
	public DirectoryString() { this(0, java.lang.Integer.MAX_VALUE); } 
}
