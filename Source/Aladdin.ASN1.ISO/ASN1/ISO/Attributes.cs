using System;
using System.Collections.Generic;
using System.Runtime.Serialization;

// Attributes ::= SET OF Attribute

namespace Aladdin.ASN1.ISO
{
	[Serializable]
	public class Attributes : Set<Attribute>
	{
		// конструктор при сериализации
        protected Attributes(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public Attributes(IEncodable encodable) : base(encodable) {} 

		// конструктор при закодировании
		public Attributes(params Attribute[] values) : base(values) {} 

		// найти требуемый атрибут
		public Attribute this[string oid] { get 
		{
			// для всех атрибутов
			foreach (Attribute attribute in this)
			{
				// проверить совпадение идентификатора
				if (attribute.Type.Value == oid) return attribute; 
			}
			return null; 
		}}
        // найти требуемый атрибут
        public static IEncodable GetAttributeValue(
            List<Attribute> attributes, string oid, int i)
        {
            // для всех атрибутов
            foreach (Attribute attribute in attributes)
            {
                // сравнить идентификатор атрибута
                if (attribute.Type.Value != oid) continue; 

                // проверить число значений атрибута
                if (attribute.Values.Length <= i) return null; 
            
                // вернуть значение
                return attribute.Values[i]; 
            }
            return null; 
        }
        // добавить требуемый атрибут
        public static void SetAttributeValues(
            List<Attribute> attributes, string oid, params IEncodable[] values) 
        {
            // указать значение атрибута
            Set<IEncodable> set = new Set<IEncodable>(values);
        
            // создать атрибут
            Attribute attribute = new Attribute(new ObjectIdentifier(oid), set); 
        
            // для всех атрибутов
            for (int i = 0; i < attributes.Count; i++)
            {
                // сравнить идентификатор атрибута
                if (attribute.Type.Value != oid) continue; 
             
                // заменить атрибут в списке
                attributes[i] = attribute; return; 
            }
            // добавить значение атрибута
            attributes.Add(attribute); 
        }
	}
}
