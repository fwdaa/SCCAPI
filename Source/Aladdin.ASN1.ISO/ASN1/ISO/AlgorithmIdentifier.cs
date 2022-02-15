using System;

//	AlgorithmIdentifier  ::=  SEQUENCE  {
//		algorithm  OBJECT IDENTIFIER,
//		parameters ANY DEFINED BY algorithm OPTIONAL  
//	}

namespace Aladdin.ASN1.ISO
{
	public class AlgorithmIdentifier : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<ObjectIdentifier>().Factory(), Cast.N), 
			new ObjectInfo(    ImplicitCreator				    .Factory  , Cast.O), 
		};
		// конструктор при раскодировании
		public AlgorithmIdentifier(IEncodable encodable) : base(encodable, info) 
		{
			// проверить наличие параметров
			if (this[1] == null) return; if (this[1].Content.Length == 0)
			{
				// установить пустой параметр
				this[1] = new Null(this[1]); return; 
			}
		}
		// конструктор при закодировании
		public AlgorithmIdentifier(ObjectIdentifier algorithm, IEncodable parameters) : 
			base(info, algorithm, parameters) {}

		public ObjectIdentifier	Algorithm	{ get { return (ObjectIdentifier)this[0]; } } 
		public IEncodable		Parameters	{ get { return                   this[1]; } }
	}
}
