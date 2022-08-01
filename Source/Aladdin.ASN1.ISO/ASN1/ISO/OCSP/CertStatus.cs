
// CertStatus ::= CHOICE {
//      good    [0] IMPLICIT NULL,
//      revoked [1] IMPLICIT RevokedInfo,
//		unknown [2] IMPLICIT NULL
// }

namespace Aladdin.ASN1.ISO.OCSP
{
	public class CertStatus : Choice
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<Null       >().Factory(), Cast.N, Tag.Context(0)), 
			new ObjectInfo(new ObjectCreator<RevokedInfo>().Factory(), Cast.N, Tag.Context(1)),  
			new ObjectInfo(new ObjectCreator<Null       >().Factory(), Cast.N, Tag.Context(2)) 
		}; 
		// конструктор
		public CertStatus() : base(info) {} 
	}
}
