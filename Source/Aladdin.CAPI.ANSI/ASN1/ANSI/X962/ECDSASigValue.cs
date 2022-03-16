using System; 
using System.Runtime.Serialization;

namespace Aladdin.ASN1.ANSI.X962
{
    ////////////////////////////////////////////////////////////////////////////////
    // EcdsaSigValue ::= SEQUENCE {
    //		r            INTEGER,
    //		s            INTEGER
    //		a            INTEGER OPTIONAL, 
    //		y CHOICE { b BOOLEAN, f FieldElement } OPTIONAL 
    // }
    ////////////////////////////////////////////////////////////////////////////////
	[Serializable]
    public class ECDSASigValue : Sequence
    {
        public class ChoiceY : Choice
        {
            // информация о структуре
            private static readonly ObjectInfo[] info = new ObjectInfo[] { 

                new ObjectInfo(new ObjectCreator<Boolean    >().Factory(), Cast.N), 
                new ObjectInfo(new ObjectCreator<OctetString>().Factory(), Cast.N)
            }; 
            // конструктор
            public ChoiceY() : base(info) {} 
        }
	    // информация о структуре
	    private static readonly ObjectInfo[] info = new ObjectInfo[] { 

		    new ObjectInfo(new ObjectCreator<Integer>().Factory(), Cast.N), 
		    new ObjectInfo(new ObjectCreator<Integer>().Factory(), Cast.N), 
            new ObjectInfo(new ObjectCreator<Integer>().Factory(), Cast.O),
            new ObjectInfo(new ChoiceCreator<ChoiceY>().Factory(), Cast.O) 
	    }; 
		// конструктор при сериализации
        protected ECDSASigValue(SerializationInfo info, StreamingContext context) : base(info, context) {}

	    // конструктор при раскодировании
	    public ECDSASigValue(IEncodable encodable) : base(encodable, info) {}

	    // конструктор при закодировании
	    public ECDSASigValue(Integer r, Integer s, Integer a, IEncodable y) : base(info, r, s, a, y) {}

	    public Integer      R { get { return (Integer)this[0]; }}
	    public Integer      S { get { return (Integer)this[1]; }}
	    public Integer      A { get { return (Integer)this[2]; }}
	    public IEncodable   Y { get { return          this[3]; }}
    }
}
