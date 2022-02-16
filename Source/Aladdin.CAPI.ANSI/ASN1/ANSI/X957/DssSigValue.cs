﻿using System;

// DssSigValue ::= SEQUENCE {
//		r            INTEGER,
//		s            INTEGER
// }

namespace Aladdin.ASN1.ANSI.X957
{
	public class DssSigValue : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<Integer>().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<Integer>().Factory(), Cast.N), 
		}; 
		// конструктор при раскодировании
		public DssSigValue(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public DssSigValue(Integer r, Integer s) : base(info, r, s) {}

		public Integer R { get { return (Integer)this[0]; } }
		public Integer S { get { return (Integer)this[1]; } }
	}
}