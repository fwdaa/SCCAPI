package aladdin.asn1.iso.pkix;
import aladdin.asn1.*; 

//	Time ::= CHOICE {
//		utcTime        UTCTime,
//		generalTime    GeneralizedTime 
//	}

public final class Time extends Choice
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(UTCTime		.class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(GeneralizedTime.class).factory(), Cast.N), 
	}; 
	// конструктор
	public Time() { super(info); } 
}
