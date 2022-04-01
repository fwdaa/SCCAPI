using System;
using System.Runtime.Serialization;
using System.Security.Cryptography.X509Certificates;

// RelativeDistinguishedNames ::= SEQUENCE OF RelativeDistinguishedName

namespace Aladdin.ASN1.ISO.PKIX
{
	[Serializable]
	public class RelativeDistinguishedNames : Sequence<RelativeDistinguishedName>
	{
		// конструктор при сериализации
        protected RelativeDistinguishedNames(SerializationInfo info, StreamingContext context) 
			
			// сохранить переданные параметры
			: base(info, context) { Init(); }

		// конструктор при раскодировании
		public RelativeDistinguishedNames(IEncodable encodable) : base(encodable) { Init(); }

		// конструктор при закодировании
		public RelativeDistinguishedNames(params RelativeDistinguishedName[] values) : base(values) { Init(); }

		// извлечь строковое имя 
		private void Init() { name = new X500DistinguishedName(Encoded).Name; }

		// конструктор по строковому имени
		public RelativeDistinguishedNames(string name) 
			
			// закодировать строко
			: base(Encodable.Decode(new X500DistinguishedName(name).RawData)) { this.name = name; }

		// раскодированное значение атрибута
		public override string ToString() { return name; } [NonSerialized] private string name; 
	}
}
