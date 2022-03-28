package aladdin.asn1.iso.pkix.ce;
import aladdin.asn1.*; 
import aladdin.asn1.iso.pkix.*; 
import java.io.*;

//	DistributionPoint ::= SEQUENCE {
//		distributionPoint [0] IMPLICIT DistributionPointName OPTIONAL,
//		reasons           [1] IMPLICIT ReasonFlags OPTIONAL,
//		cRLIssuer         [2] IMPLICIT GeneralNames OPTIONAL 
//	}

public final class DistributionPoint extends Sequence<IEncodable>
{
    private static final long serialVersionUID = -8234928854145354944L;
    
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ChoiceCreator(DistributionPointName  .class).factory(), Cast.O, Tag.context(0)), 
		new ObjectInfo(new ObjectCreator(BitFlags               .class).factory(), Cast.O, Tag.context(1)), 
		new ObjectInfo(new ObjectCreator(GeneralNames			.class).factory(), Cast.O, Tag.context(2)), 
	}; 
	// конструктор при раскодировании
	public DistributionPoint(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public DistributionPoint(IEncodable distributionPointName, BitFlags reasons, 
		GeneralNames cRLIssuer) 
	{
		super(info, distributionPointName, reasons, cRLIssuer); 
	}
	public final IEncodable     distributionPointName() { return			     get(0); } 
	public final BitFlags       reasons				 () { return (BitFlags      )get(1); }
	public final GeneralNames	crlIssuer			 () { return (GeneralNames  )get(2); }
}
