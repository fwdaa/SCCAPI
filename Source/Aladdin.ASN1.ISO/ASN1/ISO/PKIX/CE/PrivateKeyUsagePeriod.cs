using System; 

//	PrivateKeyUsagePeriod ::= SEQUENCE {
//		notBefore [0] IMPLICIT GeneralizedTime OPTIONAL,
//		notAfter  [1] IMPLICIT GeneralizedTime OPTIONAL 
//	}

namespace Aladdin.ASN1.ISO.PKIX.CE
{
	public class PrivateKeyUsagePeriod : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<GeneralizedTime>().Factory(), Cast.O, Tag.Context(0)), 
			new ObjectInfo(new ObjectCreator<GeneralizedTime>().Factory(), Cast.O, Tag.Context(1)), 
		}; 
		// конструктор при раскодировании
		public PrivateKeyUsagePeriod(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public PrivateKeyUsagePeriod(GeneralizedTime notBefore, GeneralizedTime notAfter) 
			: base(info, notBefore, notAfter) {}

		public GeneralizedTime NotBefore { get { return (GeneralizedTime)this[0]; } } 
		public GeneralizedTime NotAfter	 { get { return (GeneralizedTime)this[1]; } }
	}
}
