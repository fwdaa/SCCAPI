namespace Aladdin.ASN1.ANSI.X962
{
    ////////////////////////////////////////////////////////////////////////////////
    // SpecifiedMultiples ::= SEQUENCE OF SpecifiedMultiple
    ////////////////////////////////////////////////////////////////////////////////
    public class SpecifiedMultiples : Sequence<SpecifiedMultiple>
    {
	    // конструктор при раскодировании
	    public SpecifiedMultiples(IEncodable encodable) : base(encodable) {}  

	    // конструктор при закодировании
	    public SpecifiedMultiples(params SpecifiedMultiple[] values) : base(values) {} 
    }
}