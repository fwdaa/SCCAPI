using System;
using System.Collections.Generic;

namespace Aladdin.ISO7816
{
    ///////////////////////////////////////////////////////////////////////
    // Объект данных BER-TLV
    ///////////////////////////////////////////////////////////////////////
    public class DataObject : IEquatable<DataObject>, IComparable<DataObject>
    {
        // регистрирущий орган, тип и содержимое объекта
        private Authority authority; private Tag tag; private byte[] content;

        // конструктор закодирования
        protected DataObject(Authority authority, Tag tag) 
        { 
            // сохранить переданные параметры
            this.authority = authority; this.tag = tag; this.content = null;
        } 
         // конструктор раскодирования
        public DataObject(CompactTLV obj) : this(Authority.ISO7816, obj.Tag, obj.Value) {}

        // конструктор раскодирования
        public DataObject(Authority authority, ASN1.IEncodable encodable)

            // сохранить переданные параметры
            : this(authority, new Tag(encodable.Tag, encodable.PC), encodable.Content) {}

        // конструктор раскодирования
        public DataObject(Authority authority, Tag tag, byte[] content)
        {
            // сохранить переданные параметры
            this.authority = authority; this.tag = tag; this.content = content;
        }
        // регистрирущий орган
        public Authority Authority { get { return authority; }}

        // значение типа
        public Tag Tag { get { return tag; }}

        // содержимое объекта
        public virtual byte[] Content { 
            
            // содержимое объекта
            get { return content; } protected set { content = value; }
        }
        // хэш-код объекта
        public override int GetHashCode() { return tag.GetHashCode(); }

        // сравнить объекты
        public override bool Equals(object other)
        {
            // сравнить объекты
            return (other is DataObject) && Equals((DataObject)other); 
        }
        // сравнить объекты
        public virtual bool Equals(DataObject other) 
        { 
            // проверить совпадение ссылок
            if (Object.ReferenceEquals(other, this)) return true;
 
            // сравнить объекты
            return (other != null) ? CompareTo(other) == 0 : false; 
        }
        // сравнить объекты
        public virtual int CompareTo(DataObject other)
        {
            // сравнить типы объектов
            int cmp = Tag.CompareTo(other.Tag); if (cmp != 0) return cmp; 

            // сравнить содержимое объектов
            return Arrays.Compare(Content, other.Content); 
        }
        ///////////////////////////////////////////////////////////////////////////
        // Закодировать объект
        ///////////////////////////////////////////////////////////////////////////
        public static byte[] Encode(TagScheme tagScheme, IEnumerable<DataObject> objects)
        {
            // выделить память для закодированных представлений
            List<Byte[]> encodeds = new List<Byte[]>();  

            // для всех объектов
            foreach (DataObject obj in objects) 
            {
                // проверить наличие объекта
                if (obj == null) continue; 

                // получить закодированное представление
                encodeds.Add(obj.Encode(tagScheme).Encoded);
            }
            // объединить закодированные представления
            return Arrays.Concat(encodeds.ToArray()); 
        }
        public virtual ASN1.IEncodable Encode(TagScheme tagScheme)
        {
            // закодировать объект
            return ASN1.Encodable.Encode(Tag.AsnTag, Tag.PC, Content); 
        }
    }
}
