using System;

//	Time ::= CHOICE {
//		utcTime        UTCTime,
//		generalTime    GeneralizedTime 
//	}

namespace Aladdin.ASN1.ISO.PKIX
{
	public class Time : Choice
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<UTCTime		>().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<GeneralizedTime>().Factory(), Cast.N), 
		}; 
		// конструктор
		public Time() : base(info) {} 
	}
}
