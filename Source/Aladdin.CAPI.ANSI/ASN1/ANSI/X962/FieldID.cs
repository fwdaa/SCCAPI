using System; 
using System.Runtime.Serialization;

namespace Aladdin.ASN1.ANSI.X962
{
    ////////////////////////////////////////////////////////////////////////////////
    //	FieldID  ::=  SEQUENCE  {
    //		fieldType  OBJECT IDENTIFIER,
    //		parameters ANY DEFINED BY fieldType  
    //	}
    ////////////////////////////////////////////////////////////////////////////////
	[Serializable]
    public class FieldID : Sequence
    {
	    // информация о структуре
	    private static readonly ObjectInfo[] info = new ObjectInfo[] { 

		    new ObjectInfo(new ObjectCreator<ObjectIdentifier>().Factory(), Cast.N), 
		    new ObjectInfo(    ImplicitCreator				    .Factory  , Cast.N), 
	    };
		// конструктор при сериализации
        protected FieldID(SerializationInfo info, StreamingContext context) : base(info, context) {}

	    // конструктор при раскодировании
	    public FieldID(IEncodable encodable) : base(encodable, info) {} 

	    // конструктор при закодировании
	    public FieldID(ObjectIdentifier fieldType, IEncodable parameters) 
            : base(info, fieldType, parameters) {} 

	    public ObjectIdentifier FieldType  { get { return (ObjectIdentifier)this[0]; }} 
	    public IEncodable		Parameters { get { return                   this[1]; }}
    }
}
