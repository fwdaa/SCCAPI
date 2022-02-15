using System;

//	OtherRevocationInfoFormat ::= SEQUENCE {
//		otherRevInfoFormat	OBJECT IDENTIFIER,
//		otherRevInfo		ANY DEFINED BY otherRevInfoFormat 
//	}

namespace Aladdin.ASN1.ISO
{
	public class OtherRevocationInfoFormat : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<ObjectIdentifier>().Factory(), Cast.N), 
			new ObjectInfo(    ImplicitCreator				    .Factory  , Cast.N), 
		}; 
		// конструктор при раскодировании
		public OtherRevocationInfoFormat(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public OtherRevocationInfoFormat(ObjectIdentifier otherRevInfoFormat, IEncodable otherRevInfo) : 
			base(info, otherRevInfoFormat, otherRevInfo) {}

		public ObjectIdentifier	OtherRevInfoFormat	{ get { return (ObjectIdentifier)this[0]; } } 
		public IEncodable		OtherRevInfo		{ get { return                   this[1]; } }
	}
}
