using System;

namespace Aladdin.ASN1.GOST
{
	public class GOSTR3411DigestParameters : Choice
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<Null				>().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<ObjectIdentifier	>().Factory(), Cast.N), 
		}; 
		// конструктор
		public GOSTR3411DigestParameters() : base(info) {} 
	}
}
