using System;

//	DirectoryString ::= CHOICE {
//		teletexString       TeletexString   (SIZE (1..MAX)),
//		printableString     PrintableString (SIZE (1..MAX)),
//		universalString     UniversalString (SIZE (1..MAX)),
//		utf8String          UTF8String      (SIZE (1..MAX)),
//		bmpString           BMPString       (SIZE (1..MAX)) 
//	}

namespace Aladdin.ASN1.ISO.PKIX
{
	public class DirectoryString : Choice
	{
		// экземпляр фабрики
		public static IObjectFactory Factory(int min, int max) { return new DirectoryString(min, max); } 

		// экземпляр фабрики
		public static IObjectFactory Factory(int min) { return new DirectoryString(min); } 

		// информация о структуре
		private static ObjectInfo[] GetInfo(int min, int max) 
		{ 
			return new ObjectInfo[] { 
				new ObjectInfo(new ObjectCreator<TeletexString	>().Factory(min, max), Cast.N), 
				new ObjectInfo(new ObjectCreator<PrintableString>().Factory(min, max), Cast.N), 
				new ObjectInfo(new ObjectCreator<UniversalString>().Factory(min, max), Cast.N), 
				new ObjectInfo(new ObjectCreator<UTF8String		>().Factory(min, max), Cast.N), 
				new ObjectInfo(new ObjectCreator<BMPString		>().Factory(min, max), Cast.N), 
			}; 
		} 
		// конструктор
		public DirectoryString(int min, int max) : base(GetInfo(min, max)) {} 

		// конструктор
		public DirectoryString(int min) : this(min, Int32.MaxValue) {} 

		// конструктор
		public DirectoryString() : this(0, Int32.MaxValue) {} 
	}
}
