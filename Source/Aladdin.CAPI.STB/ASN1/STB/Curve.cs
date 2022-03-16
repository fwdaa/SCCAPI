using System;
using System.IO;
using System.Runtime.Serialization;

namespace Aladdin.ASN1.STB
{
    ////////////////////////////////////////////////////////////////////////////////
    // Curve ::= SEQUENCE {
    //  a OCTET STRING (SIZE(32|48|64)),
    //  b OCTET STRING (SIZE(32|48|64)),
    //  seed BIT STRING (SIZE(64))
    // }
    ////////////////////////////////////////////////////////////////////////////////
    [Serializable]
    public class Curve : Sequence
    {
	    // информация о структуре
	    private static readonly ObjectInfo[] info = new ObjectInfo[] { 
        
		    new ObjectInfo(new ObjectCreator<OctetString>().Factory(32, 64), Cast.N), 
		    new ObjectInfo(new ObjectCreator<OctetString>().Factory(32, 64), Cast.N), 
		    new ObjectInfo(new ObjectCreator<BitString  >().Factory(64, 64), Cast.N), 
	    }; 
		// конструктор при сериализации
        protected Curve(SerializationInfo info, StreamingContext context) : base(info, context) {}

	    // конструктор при раскодировании
	    public Curve(IEncodable encodable) : base(encodable, info) 
        {
            // определить размеры параметров
            int lengthA = A.Value.Length; int lengthB = B.Value.Length;
    
            // проверить корректность параметров
            if (lengthA != 32 && lengthA != 48 && lengthA != 64) throw new InvalidDataException(); 
            if (lengthB != 32 && lengthB != 48 && lengthB != 64) throw new InvalidDataException(); 
        }  
	    // конструктор при закодировании
	    public Curve(OctetString a, OctetString b, BitString seed) : base(info, a, b, seed) 
        {
            // определить размеры параметров
            int lengthA = A.Value.Length; int lengthB = B.Value.Length;
    
            // проверить корректность параметров
            if (lengthA != 32 && lengthA != 48 && lengthA != 64) throw new ArgumentException(); 
            if (lengthB != 32 && lengthB != 48 && lengthB != 64) throw new ArgumentException(); 
	    }
	    public OctetString A    { get { return (OctetString)this[0]; }}
	    public OctetString B    { get { return (OctetString)this[1]; }} 
	    public BitString   Seed { get { return (BitString  )this[2]; }} 
    }
}
