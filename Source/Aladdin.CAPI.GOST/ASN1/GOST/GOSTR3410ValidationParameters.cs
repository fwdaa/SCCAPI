using System; 
using System.Runtime.Serialization; 

// GostR3410-94-ValidationParameters-c ::= INTEGER (0 .. 65535)
// GostR3410-94-ValidationParameters ::= SEQUENCE {
//      x0   GostR3410-94-ValidationParameters-c,
//      c    GostR3410-94-ValidationParameters-c,
//      d    INTEGER OPTIONAL -- 1 < d < p-1 < 2^1024-1
// }
// GostR3410-94-ValidationBisParameters-c ::= INTEGER (0 .. 4294967295)
// GostR3410-94-ValidationBisParameters ::=  SEQUENCE {
//      x0   GostR3410-94-ValidationBisParameters-c,
//      c    GostR3410-94-ValidationBisParameters-c,
//      d    INTEGER OPTIONAL -- 1 < d < p-1 < 2^1024-1
// }

namespace Aladdin.ASN1.GOST
{
    [Serializable]
    public class GOSTR3410ValidationParameters : Sequence
    {
	    // информация о структуре
	    private static readonly ObjectInfo[] info = new ObjectInfo[] { 

            new ObjectInfo(new ObjectCreator<Integer>().Factory(), Cast.N), 
		    new ObjectInfo(new ObjectCreator<Integer>().Factory(), Cast.N), 
		    new ObjectInfo(new ObjectCreator<Integer>().Factory(), Cast.O) 
	    }; 
		// конструктор при сериализации
        protected GOSTR3410ValidationParameters(SerializationInfo info, StreamingContext context) : base(info, context) {}

	    // конструктор при раскодировании
	    public GOSTR3410ValidationParameters(IEncodable encodable) : base(encodable, info) {}
		
	    // конструктор при закодировании
	    public GOSTR3410ValidationParameters(Integer x0, Integer c, Integer d) : base(info, x0, c, d) {} 

	    public Integer X0 { get { return (Integer)this[0]; }}
	    public Integer C  { get { return (Integer)this[1]; }} 
	    public Integer D  { get { return (Integer)this[2]; }} 
    }
}
