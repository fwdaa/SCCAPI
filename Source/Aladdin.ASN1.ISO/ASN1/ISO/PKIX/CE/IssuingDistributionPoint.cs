using System; 
using System.IO;

// IssuingDistributionPoint ::= SEQUENCE {
//		distributionPoint          [0] IMPLICIT DistributionPointName OPTIONAL,
//		onlyContainsUserCerts      [1] IMPLICIT BOOLEAN DEFAULT FALSE,
//		onlyContainsCACerts        [2] IMPLICIT BOOLEAN DEFAULT FALSE,
//		onlySomeReasons            [3] IMPLICIT ReasonFlags OPTIONAL,
//		indirectCRL                [4] IMPLICIT BOOLEAN DEFAULT FALSE,
//		onlyContainsAttributeCerts [5] IMPLICIT BOOLEAN DEFAULT FALSE 
//	}

namespace Aladdin.ASN1.ISO.PKIX.CE
{
	public class IssuingDistributionPoint : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ChoiceCreator<DistributionPointName  >().Factory(), Cast.O, Tag.Context(0)				), 
			new ObjectInfo(new ObjectCreator<Boolean				>().Factory(), Cast.O, Tag.Context(1), Boolean.False), 
			new ObjectInfo(new ObjectCreator<Boolean				>().Factory(), Cast.O, Tag.Context(2), Boolean.False), 
			new ObjectInfo(new ObjectCreator<BitFlags				>().Factory(), Cast.O, Tag.Context(3)				), 
			new ObjectInfo(new ObjectCreator<Boolean				>().Factory(), Cast.O, Tag.Context(4), Boolean.False), 
			new ObjectInfo(new ObjectCreator<Boolean				>().Factory(), Cast.O, Tag.Context(5), Boolean.False), 
		}; 
		// конструктор при раскодировании
		public IssuingDistributionPoint(IEncodable encodable) : base(encodable, info) 
		{
			// проверить корректность значений
			if (OnlyContainsUserCerts.Value && OnlyContainsCACerts       .Value) throw new InvalidDataException(); 
			if (OnlyContainsUserCerts.Value && OnlyContainsAttributeCerts.Value) throw new InvalidDataException(); 
			if (OnlyContainsCACerts  .Value && OnlyContainsAttributeCerts.Value) throw new InvalidDataException(); 
		}
		// конструктор при закодировании
		public IssuingDistributionPoint(IEncodable distributionPoint, 
			Boolean onlyContainsUserCerts, Boolean	onlyContainsCACerts, 
			BitFlags onlySomeReasons,  Boolean indirectCRL, Boolean onlyContainsAttributeCerts) : 
			base(info, distributionPoint, onlyContainsUserCerts, onlyContainsCACerts, 
			onlySomeReasons, indirectCRL, onlyContainsAttributeCerts, onlyContainsAttributeCerts)  
		{
			// проверить корректность значений
			if (OnlyContainsUserCerts.Value && OnlyContainsCACerts       .Value) throw new ArgumentException(); 
			if (OnlyContainsUserCerts.Value && OnlyContainsAttributeCerts.Value) throw new ArgumentException(); 
			if (OnlyContainsCACerts  .Value && OnlyContainsAttributeCerts.Value) throw new ArgumentException(); 
		}
		public IEncodable	DistributionPoint			{ get { return			 this[0]; } } 
		public Boolean		OnlyContainsUserCerts		{ get { return (Boolean )this[1]; } }
		public Boolean		OnlyContainsCACerts			{ get { return (Boolean )this[2]; } }
		public BitFlags		OnlySomeReasons				{ get { return (BitFlags)this[3]; } }
		public Boolean		IndirectCRL					{ get { return (Boolean )this[4]; } }
		public Boolean		OnlyContainsAttributeCerts	{ get { return (Boolean )this[5]; } }
	}
}
