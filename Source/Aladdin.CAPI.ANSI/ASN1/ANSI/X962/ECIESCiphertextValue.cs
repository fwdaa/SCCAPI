namespace Aladdin.ASN1.ANSI.X962
{
    ////////////////////////////////////////////////////////////////////////////////
    // ECIES-Ciphertext-Value ::= SEQUENCE {
    //      ephemeralPublicKey ECPoint,
    //      symmetricCiphertext OCTET STRING,
    //      macTag OCTET STRING
    // }
    ////////////////////////////////////////////////////////////////////////////////
    public class ECIESCiphertextValue : Sequence
    {
	    // информация о структуре
	    private static readonly ObjectInfo[] info = new ObjectInfo[] { 

		    new ObjectInfo(new ObjectCreator<OctetString>().Factory(), Cast.N), 
		    new ObjectInfo(new ObjectCreator<OctetString>().Factory(), Cast.N), 
		    new ObjectInfo(new ObjectCreator<OctetString>().Factory(), Cast.N), 
	    }; 
	    // конструктор при раскодировании
	    public ECIESCiphertextValue(IEncodable encodable) : base(encodable, info) {}

	    // конструктор при закодировании
	    public ECIESCiphertextValue(OctetString ephemeralPublicKey, 
            OctetString symmetricCiphertext, OctetString macTag) 
                : base(info, ephemeralPublicKey, symmetricCiphertext, macTag) {}

	    public OctetString EphemeralPublicKey  { get { return (OctetString)this[0]; }}
	    public OctetString SymmetricCiphertext { get { return (OctetString)this[1]; }}
	    public OctetString MacTag              { get { return (OctetString)this[2]; }}
    }
}