package aladdin.asn1.iso.pkix;
import aladdin.asn1.*; 
import java.util.*;
import java.io.*; 

//	Validity ::= SEQUENCE {
//		notBefore      Time,
//		notAfter       Time  
//	}

public final class Validity extends Sequence<VisibleString>
{
    private static final long serialVersionUID = 1681565745523487026L;
    
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ChoiceCreator(Time.class).factory(), Cast.N), 
		new ObjectInfo(new ChoiceCreator(Time.class).factory(), Cast.N), 
	}; 
	// конструктор при раскодировании
	public Validity(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public Validity(VisibleString notBefore, VisibleString notAfter) 
	{
		super(info, notBefore, notAfter); 
	}
	public final VisibleString notBefore() { return get(0); } 
	public final VisibleString notAfter () { return get(1); }
	
    // раскодированное время
    public final Date notBeforeDate() 
	{ 
		// получить время 
		VisibleString encodable = get(0); return (encodable instanceof UTCTime) ? 
		
			// раскодировать время
			((UTCTime)encodable).date() : ((GeneralizedTime)encodable).date(); 
	}
    // раскодированное время
    public final Date notAfterDate() 
	{ 
		// получить время 
		VisibleString encodable = get(1); return (encodable instanceof UTCTime) ? 
		
			// раскодировать время
			((UTCTime)encodable).date() : ((GeneralizedTime)encodable).date(); 
	}
}
