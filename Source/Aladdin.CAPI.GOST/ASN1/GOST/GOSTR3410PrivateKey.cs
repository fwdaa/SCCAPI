using System;

///////////////////////////////////////////////////////////////////////////////
// GostR3410-2001-KeyValueMask ::= OCTET STRING;
// GostR3410-2001-PublicKey    ::= OCTET STRING {PubKeyX | PubKeyY};
// GostR3410-2001-KeyValueInfo ::= SEQUENCE{
// 	GostR3410-2001-KeyValueMask,
// 	GostR3410-2001-PublicKey 
// }
//	GostR3410-2001-PrivateKey ::= CHOICE {
//		GostR3410-2001-KeyValueMask,
//		GostR3410-2001-KeyValueInfo 
// }
///////////////////////////////////////////////////////////////////////////////
namespace Aladdin.ASN1.GOST
{
	public class GOSTR3410PrivateKey : Choice
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<OctetString                 >().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<GOSTR3410PrivateKeyValueInfo>().Factory(), Cast.N), 
		}; 
		// конструктор
		public GOSTR3410PrivateKey() : base(info) {} 
	}
}
