namespace Aladdin.ASN1.ANSI.X962
{
    // ECPoints ::= SEQUENCE OF ECPoint

    public class ECPoints : Sequence<OctetString>
    {
	    // конструктор при раскодировании
	    public ECPoints(IEncodable encodable) : base(encodable) {} 

	    // конструктор при закодировании
	    public ECPoints(params OctetString[] values) : base(values) {} 
    }
}