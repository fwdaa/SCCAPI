using System; 
using System.Runtime.Serialization;

namespace Aladdin.ASN1.STB
{
    ////////////////////////////////////////////////////////////////////////////////
    // FieldID ::= SEQUENCE {
    //  fieldType OBJECT IDENTIFIER (bign-primefield),
    //  parameters INTEGER
    // }
    ////////////////////////////////////////////////////////////////////////////////
    [Serializable]
    public class FieldID : Sequence
    {
	    // информация о структуре
	    private static readonly ObjectInfo[] info = new ObjectInfo[] { 
        
		    new ObjectInfo(new ObjectCreator<ObjectIdentifier>().Factory(), Cast.N), 
		    new ObjectInfo(new ObjectCreator<Integer         >().Factory(), Cast.N), 
	    }; 
		// конструктор при сериализации
        protected FieldID(SerializationInfo info, StreamingContext context) : base(info, context) {}

	    // конструктор при раскодировании
	    public FieldID(IEncodable encodable) : base(encodable, info) {}  
    
	    // конструктор при закодировании
	    public FieldID(ObjectIdentifier fieldType, Integer parameters)
		    : base(info, fieldType, parameters) {}  

	    public ObjectIdentifier FieldType  { get { return (ObjectIdentifier )this[0]; }} 
	    public Integer          Parameters { get { return (Integer          )this[1]; }} 
    }
}
