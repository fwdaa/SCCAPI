using System; 
using System.Runtime.Serialization;

namespace Aladdin.ASN1.ANSI.X962
{
    // ECCAlgorithms ::= SEQUENCE OF ECCAlgorithm

	[Serializable]
    public class ECCAlgorithms : Sequence<ISO.AlgorithmIdentifier>
    {
		// конструктор при сериализации
        protected ECCAlgorithms(SerializationInfo info, StreamingContext context) : base(info, context) {}

	    // конструктор при раскодировании
	    public ECCAlgorithms(IEncodable encodable) : base(encodable) {} 

	    // конструктор при закодировании
	    public ECCAlgorithms(params ISO.AlgorithmIdentifier[] values) : base(values) {}

	    // найти требуемый атрибут
	    public ISO.AlgorithmIdentifier this[string oid] { get
	    {
		    // для всех атрибутов
		    foreach (ISO.AlgorithmIdentifier algorithm in this)
		    {
			    // проверить совпадение идентификатора
			    if (algorithm.Algorithm.Value.Equals(oid)) return algorithm; 
		    }
		    return null; 
	    }}
    }
}