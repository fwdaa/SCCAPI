using System;
using System.Collections;
using System.Collections.Generic;

namespace Aladdin.ISO7816
{
    ///////////////////////////////////////////////////////////////////////////
    // Составной объект BER-TLV
    ///////////////////////////////////////////////////////////////////////////
    public class DataObjectTemplate : DataObject, IEnumerable<DataObject>, IComparable<DataObjectTemplate>
    {
        // внутренние объекты
        private List<DataObject> objects;

        // конструктор закодирования
        public DataObjectTemplate(Authority authority, Tag tag, params DataObject[] objects) : base(authority, tag)
        {
            // проверить корректность данных
            if (tag.PC != ASN1.PC.Constructed) throw new ArgumentException(); 
            
            // сохранить переданные параметры
            this.objects = new List<DataObject>(objects);
        }
        // конструктор раскодирования
        public DataObjectTemplate(Authority authority, TagScheme tagScheme, ASN1.IEncodable encodable)

            // сохранить переданные параметры
            : this(authority, new Tag(encodable.Tag, encodable.PC), tagScheme, encodable.Content) {}

        // конструктор раскодирования
        public DataObjectTemplate(Authority authority, Tag tag, TagScheme tagScheme, byte[] content) : base(authority, tag)
        {
            // проверить корректность данных
            if (tag.PC != ASN1.PC.Constructed) throw new ArgumentException(); 

            // создать список закодированных представлений
            List<ASN1.IEncodable> encodables = new List<ASN1.IEncodable>(); 

            // для всех внутренних объектов
            for (int offset = 0; offset < content.Length; )
            { 
                // раскодировать содержимое
                ASN1.IEncodable encodable = ASN1.Encodable.Decode(
                    content, offset, content.Length - offset
                ); 
                // перейти на следующий объект
                encodables.Add(encodable); offset += encodable.Encoded.Length; 
            }
            // раскодировать объекты
            objects = new List<DataObject>(tagScheme.Decode(authority, encodables)); 
        }
	    // перечислитель объектов
	    IEnumerator IEnumerable.GetEnumerator() { return objects.GetEnumerator(); }

	    // перечислитель объектов
	    public IEnumerator<DataObject> GetEnumerator() { return objects.GetEnumerator(); }

        // число элементов
        public int Count { get { return objects.Count; }}

	    // получить элемент коллекции
	    public DataObject this[int index] { get { return objects[index]; }}

	    // получить элемент коллекции
	    public DataObject[] this[Tag tag] { get { 

            // создать список объектов
            List<DataObject> objs = new List<DataObject>(); 

            // найти внутренний объект
            foreach (DataObject obj in objects) 
            {
                // проверить совпадение идентификаторов
                if (obj.Tag == tag) objs.Add(obj);
            }
            // вернуть список объектов
            return objs.ToArray(); 
        }}
        // сравнить объекты
        public override int CompareTo(DataObject other)
        {
            // проверить совпадение ссылок
            if (Object.ReferenceEquals(other, this)) return 0; 

            // сравнить типы объектов
            int cmp = Tag.CompareTo(other.Tag); if (cmp != 0) return cmp; 

            // сравнить объекты
            return CompareTo((DataObjectTemplate)other); 
        }
        // сравнить объекты
        public virtual int CompareTo(DataObjectTemplate other) 
        { 
            // проверить совпадение ссылок
            if (Object.ReferenceEquals(other, this)) return 0; 

            // сравнить типы объектов
            int cmp = Tag.CompareTo(other.Tag); 

            // для всех объектов
            for (int i = 0; cmp == 0 && i < objects.Count; i++)
            {
                // проверить наличие объекта
                if (other.objects.Count <= i) return 1; 

                // сравнить значения объектов
                cmp = objects[i].CompareTo(other.objects[i]); 
            }
            // проверить совпадение объектов
            if (cmp != 0) return cmp; 

            // проверить совпадение размеров
            return (objects.Count == other.objects.Count) ? 0 : -1; 
        }
        ///////////////////////////////////////////////////////////////////////////
        // Закодировать объект
        ///////////////////////////////////////////////////////////////////////////
        public override ASN1.IEncodable Encode(TagScheme tagScheme)
        { 
            // закодировать внутренние объекты
            byte[] content = DataObject.Encode(tagScheme, objects); 
        
            // закодировать составной объект
            return ASN1.Encodable.Encode(Tag.AsnTag, Tag.PC, content); 
        }
    }
}
