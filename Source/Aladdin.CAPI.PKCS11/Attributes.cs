using System;
using System.Collections;
using System.Collections.Generic;

namespace Aladdin.CAPI.PKCS11
{
    ///////////////////////////////////////////////////////////////////////////////
    // Атрибуты ключа PKCS11
    ///////////////////////////////////////////////////////////////////////////////
    public class Attributes : IEnumerable<Attribute>
    {
        // атрибуты ключа
	    private Dictionary<UInt64, Attribute> attributes; 

	    // конструктор
	    public Attributes() 
        {
            // создать набор атрибутов
            this.attributes = new Dictionary<UInt64, Attribute>(); 
        }
	    // конструктор
	    public Attributes(Dictionary<UInt64, Attribute> attributes) 
        {
            // сохранить переданные параметры
            this.attributes = attributes; 
        }
	    // конструктор
	    public Attributes(params Attribute[] attributes) 
	    {
            // создать набор атрибутов
            this.attributes = new Dictionary<UInt64, Attribute>(); 
        
		    // проверить наличие атрибутов
		    if (attributes == null || attributes.Length == 0) return; 
        
            // для всех атрибутов
            foreach (Attribute attribute in attributes) 
            {
                // добавить атрибут в набор
                this.attributes.Add(attribute.Type, attribute);
            }
	    }
        // перечисление элементов
        public IEnumerator<Attribute> GetEnumerator()
        {
            // перечисление элементов
            return attributes.Values.GetEnumerator(); 
        }
        // перечисление элементов
        IEnumerator IEnumerable.GetEnumerator()
        {
            // перечисление элементов
            return attributes.Values.GetEnumerator(); 
        }
        // число атрибутов
        public int Count { get { return attributes.Count; }}

        // получить список атрибутов
        public Attribute[] ToArray()
        {
            // создать список атрибутов
            List<Attribute> attrs = new List<Attribute>(); 

            // для всех атрибутов
            foreach (Attribute attribute in attributes.Values)
            {
                // добавить атрибут в список
                attrs.Add(attribute); 
            }
            return attrs.ToArray(); 
        }
	    // найти атрибут
	    public Attribute this[ulong type] { get 
        { 
            // проверить наличие атрибута
		    if (!attributes.ContainsKey(type)) return null; 

			// вернуть найденный атрибут
			return attributes[type]; 
		}}
	    // объединить списки атрибутов
	    public Attributes Join(params Attribute[] attributes)
	    {
		    // проверить наличие атрибутов
		    if (attributes == null || attributes.Length == 0) return this; 
        
            // создать набор атрибутов
            Dictionary<UInt64, Attribute> result = 
			    new Dictionary<UInt64, Attribute>(this.attributes); 

            // для всех атрибутов
            foreach (Attribute attribute in attributes) 
            {
			    // при наличии атрибута заменить атрибут в наборе
			    if (result.ContainsKey(attribute.Type)) result[attribute.Type] = attribute; 

                // добавить атрибут в набор
                else result.Add(attribute.Type, attribute);
            }
            // вернуть набор атрибутов
            return new Attributes(result); 
        }
	    // объединить списки атрибутов
	    public Attributes Join(IEnumerable<Attribute> attributes)
	    {
		    // проверить наличие атрибутов
		    if (attributes == null) return this; 
        
            // создать набор атрибутов
            Dictionary<UInt64, Attribute> result = 
			    new Dictionary<UInt64, Attribute>(this.attributes); 

            // для всех атрибутов
            foreach (Attribute attribute in attributes) 
            {
			    // при наличии атрибута заменить атрибут в наборе
			    if (result.ContainsKey(attribute.Type)) result[attribute.Type] = attribute; 

                // добавить атрибут в набор
                else result.Add(attribute.Type, attribute);
            }
            // вернуть набор атрибутов
            return new Attributes(result); 
        }
    };
}
