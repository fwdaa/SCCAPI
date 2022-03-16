using System; 
using System.Runtime.Serialization;

namespace Aladdin.ASN1.ANSI.X962
{
    ////////////////////////////////////////////////////////////////////////////////
    // SpecifiedMultiples ::= SEQUENCE {
    //      multiple INTEGER,
    //      point ECPoint 
    // }
    ////////////////////////////////////////////////////////////////////////////////
	[Serializable]
    public class SpecifiedMultiple : Sequence
    {
	    // информация о структуре
	    private static readonly ObjectInfo[] info = new ObjectInfo[] { 

		    new ObjectInfo(new ObjectCreator<Integer    >().Factory(), Cast.N), 
		    new ObjectInfo(new ObjectCreator<OctetString>().Factory(), Cast.N), 
	    }; 
		// конструктор при сериализации
        protected SpecifiedMultiple(SerializationInfo info, StreamingContext context) : base(info, context) {}

	    // конструктор при раскодировании
	    public SpecifiedMultiple(IEncodable encodable) : base(encodable, info) {}

	    // конструктор при закодировании
	    public SpecifiedMultiple(Integer multiple, OctetString point) : base(info, multiple, point) {}

	    public Integer     Multiple { get { return (Integer    )this[0]; }}
	    public OctetString Point    { get { return (OctetString)this[1]; }}
    }
}