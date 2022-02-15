using System;
using System.IO;

// RC5-CBC-Parameters ::= SEQUENCE {
//		version		INTEGER	{v1-0(16)} (v1-0),
//		rounds		INTEGER	(0..127),
//		blockSize	INTEGER	(64 | 128),
//		iv			OCTET STRING OPTIONAL
//	}

namespace Aladdin.ASN1.ANSI.RSA
{
	public class RC5CBCParameter : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<Integer		>().Factory(       ), Cast.N), 
			new ObjectInfo(new ObjectCreator<Integer		>().Factory( 0, 127), Cast.N), 
			new ObjectInfo(new ObjectCreator<Integer		>().Factory(64, 128), Cast.N), 
			new ObjectInfo(new ObjectCreator<OctetString	>().Factory(       ), Cast.O), 
		}; 
		// конструктор при раскодировании
		public RC5CBCParameter(IEncodable encodable) : base(encodable, info) 
		{
			// проверить ограничение
			if (BlockSize.Value.IntValue != 64 && BlockSize.Value.IntValue != 128) 
			{
				// при ошибке выбросить исключение
				throw new InvalidDataException(); 
			}
		}
		// конструктор при закодировании
		public RC5CBCParameter(Integer version, Integer rounds, Integer blockSize, OctetString iv) : 
			base(info, version, rounds, blockSize, iv) 
		{
			// проверить ограничение
			if (BlockSize.Value.IntValue != 64 && BlockSize.Value.IntValue != 128) 
			{
				// при ошибке выбросить исключение
				throw new ArgumentException(); 
			}
		}
		public Integer		Version		{ get { return (Integer	   )this[0]; } }
		public Integer		Rounds		{ get { return (Integer	   )this[1]; } }
		public Integer		BlockSize	{ get { return (Integer	   )this[2]; } }
		public OctetString	IV			{ get { return (OctetString)this[3]; } }
	}
}
