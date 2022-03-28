package aladdin.asn1.iso.pkix;
import aladdin.asn1.*; 
import java.io.*;

//	EDIPartyName ::= SEQUENCE {
//		nameAssigner [0] IMPLICIT DirectoryString OPTIONAL,
//		partyName    [1] IMPLICIT DirectoryString 
//	}

public final class EDIPartyName extends Sequence<OctetString>
{
    private static final long serialVersionUID = 1627598266681309836L;
    
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ChoiceCreator(DirectoryString.class).factory(), Cast.O, Tag.context(0)), 
		new ObjectInfo(new ChoiceCreator(DirectoryString.class).factory(), Cast.N, Tag.context(1)), 
	}; 
	// конструктор при раскодировании
	public EDIPartyName(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public EDIPartyName(OctetString nameAssigner, OctetString partyName) 
	{
		super(info, nameAssigner, partyName); 
	}
	public final OctetString nameAssigner() { return get(0); } 	
	public final OctetString partyName   () { return get(1); }
}
