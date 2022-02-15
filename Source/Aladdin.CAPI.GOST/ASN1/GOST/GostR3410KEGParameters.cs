///////////////////////////////////////////////////////////////////////////////
// GostR3410-12-KEG-Parameters ::= SEQUENCE
// {
//      algorithm OBJECT IDENTIFIER
// }
///////////////////////////////////////////////////////////////////////////////
namespace Aladdin.ASN1.GOST
{
	public class GOSTR3410KEGParameters : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<ObjectIdentifier>().Factory(), Cast.N), 
		}; 
		// конструктор при раскодировании
		public GOSTR3410KEGParameters(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public GOSTR3410KEGParameters(ObjectIdentifier algorithm) : base(info, algorithm) {}

		public ObjectIdentifier	Algorithm { get { return (ObjectIdentifier)this[0]; } } 
	}

}
