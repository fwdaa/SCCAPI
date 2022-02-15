using System; 

//	DistributionPoint ::= SEQUENCE {
//		distributionPoint [0] IMPLICIT DistributionPointName OPTIONAL,
//		reasons           [1] IMPLICIT ReasonFlags OPTIONAL,
//		cRLIssuer         [2] IMPLICIT GeneralNames OPTIONAL 
//	}

namespace Aladdin.ASN1.ISO.PKIX.CE
{
	public class DistributionPoint : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ChoiceCreator<DistributionPointName  >().Factory(), Cast.O, Tag.Context(0)), 
			new ObjectInfo(new ObjectCreator<BitFlags				>().Factory(), Cast.O, Tag.Context(1)), 
			new ObjectInfo(new ObjectCreator<GeneralNames			>().Factory(), Cast.O, Tag.Context(2)), 
		}; 
		// конструктор при раскодировании
		public DistributionPoint(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public DistributionPoint(IEncodable distributionPointName, BitFlags reasons, 
			GeneralNames cRLIssuer) : base(info, distributionPointName, reasons, cRLIssuer) {}

		public IEncodable	DistributionPointName	{ get { return				 this[0]; }} 
		public BitFlags		Reasons					{ get { return (BitFlags	)this[1]; }}
		public GeneralNames	CRLIssuer				{ get { return (GeneralNames)this[2]; }}
	}
}
