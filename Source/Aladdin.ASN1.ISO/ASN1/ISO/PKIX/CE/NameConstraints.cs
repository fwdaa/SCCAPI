using System; 

//	NameConstraints ::= SEQUENCE {
//		permittedSubtrees [0] IMPLICIT GeneralSubtrees OPTIONAL,
//		excludedSubtrees  [1] IMPLICIT GeneralSubtrees OPTIONAL 
//	}

namespace Aladdin.ASN1.ISO.PKIX.CE
{
	public class NameConstraints : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<GeneralSubtrees>().Factory(), Cast.O, Tag.Context(0)), 
			new ObjectInfo(new ObjectCreator<GeneralSubtrees>().Factory(), Cast.O, Tag.Context(1)), 
		}; 
		// конструктор при раскодировании
		public NameConstraints(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public NameConstraints(GeneralSubtrees permittedSubtrees, GeneralSubtrees excludedSubtrees) : 
			base(info, permittedSubtrees, excludedSubtrees){}

		public GeneralSubtrees PermittedSubtrees { get { return (GeneralSubtrees)this[0]; } } 
		public GeneralSubtrees ExcludedSubtrees  { get { return (GeneralSubtrees)this[1]; } }
	}
}
