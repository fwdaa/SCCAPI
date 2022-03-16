using System; 
using System.Runtime.Serialization;

namespace Aladdin.ASN1.ANSI.X962
{
    ////////////////////////////////////////////////////////////////////////////////
    // Characteristic-two ::= SEQUENCE {
    //      m           INTEGER,                      -- Field size 2^m
    //      basis       OBJECT IDENTIFIER,
    //      parameters  ANY DEFINED BY basis 
    // }
    ////////////////////////////////////////////////////////////////////////////////
	[Serializable]
    public class CharacteristicTwo : Sequence
    {
	    // информация о структуре
	    private static readonly ObjectInfo[] info = new ObjectInfo[] { 

		    new ObjectInfo(new ObjectCreator<Integer         >().Factory(), Cast.N), 
		    new ObjectInfo(new ObjectCreator<ObjectIdentifier>().Factory(), Cast.N), 
		    new ObjectInfo(    ImplicitCreator				    .Factory  , Cast.N), 
	    }; 
		// конструктор при сериализации
        protected CharacteristicTwo(SerializationInfo info, StreamingContext context) : base(info, context) {}

	    // конструктор при раскодировании
	    public CharacteristicTwo(IEncodable encodable) : base(encodable, info) {}

	    // конструктор при закодировании
	    public CharacteristicTwo(Integer m, ObjectIdentifier basis, IEncodable parameters) 
            : base(info, m, basis, parameters) {} 

	    public Integer          M          { get { return (Integer         )this[0]; }}
	    public ObjectIdentifier Basis      { get { return (ObjectIdentifier)this[1]; }}
	    public IEncodable       Parameters { get { return                   this[2]; }}
    }
}
