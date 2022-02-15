namespace Aladdin.ASN1.ANSI.X962
{
    ////////////////////////////////////////////////////////////////////////////////
    // ECPrivateKey ::= SEQUENCE {
    //      version INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
    //      privateKey OCTET STRING,
    //      parameters [0] EXPLICIT ECDomainParameters {{ SECGCurveNames }} OPTIONAL,
    //      publicKey  [1] EXPLICIT BIT STRING OPTIONAL
    // }
    ////////////////////////////////////////////////////////////////////////////////
    public class ECPrivateKey : Sequence
    {
	    // информация о структуре
	    private static readonly ObjectInfo[] info = new ObjectInfo[] { 

		    new ObjectInfo(new ObjectCreator<Integer            >().Factory(), Cast.N,  Tag.Any       ), 
		    new ObjectInfo(new ObjectCreator<OctetString        >().Factory(), Cast.N,  Tag.Any       ), 
		    new ObjectInfo(new ChoiceCreator<ECDomainParameters >().Factory(), Cast.EO, Tag.Context(0)),
		    new ObjectInfo(new ObjectCreator<BitString          >().Factory(), Cast.EO, Tag.Context(1)) 
	    }; 
	    // конструктор при раскодировании
	    public ECPrivateKey(IEncodable encodable) : base(encodable, info) {}

	    // конструктор при закодировании
	    public ECPrivateKey(Integer version, OctetString privateKey, 
            IEncodable parameters, BitString publicKey) 
                : base(info, version, privateKey, parameters, publicKey) {} 

	    public Integer     Version    { get { return (Integer    )this[0]; }}
	    public OctetString PrivateKey { get { return (OctetString)this[1]; }}
	    public IEncodable  Parameters { get { return              this[2]; }}
	    public BitString   PublicKey  { get { return (BitString  )this[3]; }}
    }
}
