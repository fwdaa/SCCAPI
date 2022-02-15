using System;

//	Validity ::= SEQUENCE {
//		notBefore      Time,
//		notAfter       Time  
//	}

namespace Aladdin.ASN1.ISO.PKIX
{
	public class Validity : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ChoiceCreator<Time>().Factory(), Cast.N), 
			new ObjectInfo(new ChoiceCreator<Time>().Factory(), Cast.N), 
		}; 
		// конструктор при раскодировании
		public Validity(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public Validity(VisibleString notBefore, VisibleString notAfter) : 
			base(info, notBefore, notAfter) {}

		public VisibleString NotBefore { get { return (VisibleString)this[0]; } } 
		public VisibleString NotAfter  { get { return (VisibleString)this[1]; } }

        // раскодированное время
        public DateTime NotBeforeDate { get  
	    { 
		    // получить время 
		    VisibleString encodable = NotBefore; return (encodable is UTCTime) ? 
		
			    // раскодировать время
			    ((UTCTime)encodable).Value : ((GeneralizedTime)encodable).Value; 
	    }}
        // раскодированное время
        public DateTime NotAfterDate { get 
	    { 
		    // получить время 
		    VisibleString encodable = NotAfter; return (encodable is UTCTime) ? 
		
			    // раскодировать время
			    ((UTCTime)encodable).Value : ((GeneralizedTime)encodable).Value; 
	    }}
	}
}
