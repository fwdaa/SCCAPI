using System; 

//	DistributionPointName ::= CHOICE {
//		fullName                [0] IMPLICIT GeneralNames,
//		nameRelativeToCRLIssuer [1] IMPLICIT RelativeDistinguishedName 
//	}

namespace Aladdin.ASN1.ISO.PKIX.CE
{
	public class DistributionPointName : Choice
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<GeneralNames				>().Factory(), Cast.N, Tag.Context(0)), 
			new ObjectInfo(new ObjectCreator<RelativeDistinguishedName  >().Factory(), Cast.N, Tag.Context(1)), 
		}; 
		// конструктор
		public DistributionPointName() : base(info) {} 
	}
}
