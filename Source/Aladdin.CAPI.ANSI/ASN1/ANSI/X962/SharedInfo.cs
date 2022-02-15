namespace Aladdin.ASN1.ANSI.X962
{
    ////////////////////////////////////////////////////////////////////////////////
    // ASN1SharedInfo ::= SEQUENCE {
    //      keyInfo AlgorithmIdentifier,
    //      entityUInfo  [0] EXPLICIT OCTET STRING OPTIONAL,
    //      entityVInfo  [1] EXPLICIT OCTET STRING OPTIONAL,
    //      suppPubInfo  [2] EXPLICIT OCTET STRING OPTIONAL,
    //      suppPrivInfo [3] EXPLICIT OCTET STRING OPTIONAL
    // }
    ////////////////////////////////////////////////////////////////////////////////
    public class SharedInfo : Sequence
    {
	    // информация о структуре
	    private static readonly ObjectInfo[] info = new ObjectInfo[] { 

		    new ObjectInfo(new ObjectCreator<ISO.AlgorithmIdentifier>().Factory(), Cast.EO, Tag.Any       ), 
		    new ObjectInfo(new ObjectCreator<OctetString            >().Factory(), Cast.N , Tag.Context(0)), 
		    new ObjectInfo(new ObjectCreator<OctetString            >().Factory(), Cast.EO, Tag.Context(1)),
		    new ObjectInfo(new ObjectCreator<OctetString            >().Factory(), Cast.EO, Tag.Context(2)), 
		    new ObjectInfo(new ObjectCreator<OctetString            >().Factory(), Cast.EO, Tag.Context(3)) 
	    }; 
	    // конструктор при раскодировании
	    public SharedInfo(IEncodable encodable) : base(encodable, info) {}

	    // конструктор при закодировании
	    public SharedInfo(ISO.AlgorithmIdentifier keyInfo, OctetString entityUInfo, 
            OctetString entityVInfo, OctetString suppPubInfo, OctetString suppPrivInfo) 
                : base(info, keyInfo, entityUInfo, entityVInfo, suppPubInfo, suppPrivInfo) {}
 
	    public ISO.AlgorithmIdentifier KeyInfo      { get { return (ISO.AlgorithmIdentifier )this[0]; }}
	    public OctetString             EntityUInfo  { get { return (OctetString             )this[1]; }}
	    public OctetString             EntityVInfo  { get { return (OctetString             )this[2]; }}
	    public OctetString             SuppPubInfo  { get { return (OctetString             )this[3]; }}
	    public OctetString             SuppPrivInfo { get { return (OctetString             )this[4]; }}
    }
}
