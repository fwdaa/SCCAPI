package aladdin.asn1.iso.pkix.ce;
import aladdin.asn1.*; 
import aladdin.asn1.Boolean; 
import java.io.*; 

// IssuingDistributionPoint ::= SEQUENCE {
//		distributionPoint          [0] IMPLICIT DistributionPointName OPTIONAL,
//		onlyContainsUserCerts      [1] IMPLICIT BOOLEAN DEFAULT FALSE,
//		onlyContainsCACerts        [2] IMPLICIT BOOLEAN DEFAULT FALSE,
//		onlySomeReasons            [3] IMPLICIT ReasonFlags OPTIONAL,
//		indirectCRL                [4] IMPLICIT BOOLEAN DEFAULT FALSE,
//		onlyContainsAttributeCerts [5] IMPLICIT BOOLEAN DEFAULT FALSE 
//	}

public final class IssuingDistributionPoint extends Sequence<IEncodable>
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ChoiceCreator(DistributionPointName  .class).factory(), Cast.O, Tag.context(0)					), 
		new ObjectInfo(new ObjectCreator(Boolean                .class).factory(), Cast.O, Tag.context(1), Boolean.FALSE), 
		new ObjectInfo(new ObjectCreator(Boolean                .class).factory(), Cast.O, Tag.context(2), Boolean.FALSE), 
		new ObjectInfo(new ObjectCreator(BitFlags               .class).factory(), Cast.O, Tag.context(3)					), 
		new ObjectInfo(new ObjectCreator(Boolean                .class).factory(), Cast.O, Tag.context(4), Boolean.FALSE), 
		new ObjectInfo(new ObjectCreator(Boolean                .class).factory(), Cast.O, Tag.context(5), Boolean.FALSE), 
	}; 
	// конструктор при раскодировании
	public IssuingDistributionPoint(IEncodable encodable) throws IOException 
	{
		super(encodable, info); 
		
		// проверить корректность значений
		if (onlyContainsUserCerts().value() && onlyContainsCACerts	     ().value()) throw new IOException(); 
		if (onlyContainsUserCerts().value() && onlyContainsAttributeCerts().value()) throw new IOException(); 
		if (onlyContainsCACerts  ().value() && onlyContainsAttributeCerts().value()) throw new IOException(); 
	}
	// конструктор при закодировании
	public IssuingDistributionPoint(IEncodable distributionPoint, 
		Boolean onlyContainsUserCerts, Boolean onlyContainsCACerts, 
        BitFlags onlySomeReasons, Boolean indirectCRL, 
		Boolean onlyContainsAttributeCerts) 
	{
		super(info, distributionPoint, onlyContainsUserCerts, 
			onlyContainsCACerts, onlySomeReasons, indirectCRL, 
			onlyContainsAttributeCerts, onlyContainsAttributeCerts); 
				
		// проверить корректность значений
		if (onlyContainsUserCerts.value() && onlyContainsCACerts       .value()) throw new IllegalArgumentException(); 
		if (onlyContainsUserCerts.value() && onlyContainsAttributeCerts.value()) throw new IllegalArgumentException(); 
		if (onlyContainsCACerts  .value() && onlyContainsAttributeCerts.value()) throw new IllegalArgumentException(); 
	}
	public final IEncodable	distributionPoint			() { return				 get(0); } 
	public final Boolean	onlyContainsUserCerts		() { return (Boolean	)get(1); }
	public final Boolean	onlyContainsCACerts			() { return (Boolean	)get(2); }
	public final BitFlags	onlySomeReasons				() { return (BitFlags	)get(3); }
	public final Boolean	indirectCRL					() { return (Boolean	)get(4); }
	public final Boolean	onlyContainsAttributeCerts	() { return (Boolean	)get(5); }
}
