using System; 

//	DisplayText ::= CHOICE {
//		ia5String     IA5String      (SIZE (1..200)),
//		visibleString VisibleString  (SIZE (1..200)),
//		bmpString     BMPString      (SIZE (1..200)),
//		utf8String    UTF8String     (SIZE (1..200)) 
//	}

namespace Aladdin.ASN1.ISO.PKIX.CE
{
	public class DisplayText : Choice
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<IA5String	    >().Factory(1, 200), Cast.N), 
			new ObjectInfo(new ObjectCreator<VisibleString  >().Factory(1, 200), Cast.N), 
			new ObjectInfo(new ObjectCreator<BMPString	    >().Factory(1, 200), Cast.N), 
			new ObjectInfo(new ObjectCreator<UTF8String	    >().Factory(1, 200), Cast.N), 
		}; 
		// конструктор
		public DisplayText() : base(info) {} 
	}
}
