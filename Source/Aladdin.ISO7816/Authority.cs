using System;
using System.Collections.Generic;

namespace Aladdin.ISO7816
{
    ///////////////////////////////////////////////////////////////////////////
    // Регистрирующий орган
    ///////////////////////////////////////////////////////////////////////////
    public class Authority : IEquatable<Authority>
    { 
        // стандарт ISO 7816
        public static readonly Authority ISO7816 = new Authority(); 

        // объекты идентификации
        private List<DataObject> objects;

        // конструктор
        private Authority() { objects = new List<DataObject>();

            // указать идентификатор стандарта
            objects.Add(new DataObject(this, new ASN1.ObjectIdentifier("1.0.7816"))); 
        }
        // конструктор
        public Authority(IEnumerable<DataObject> objects) 
        { 
            // создать и отсортировать список объектов
            this.objects = new List<DataObject>(objects); this.objects.Sort();
        } 
        // объекты идентификации
        public DataObject[] Objects { get { return objects.ToArray(); }}

        // конструктор
        public override int GetHashCode() { int code = 0; 

            // вычислить хэш-код
            foreach (DataObject obj in objects) code ^= obj.GetHashCode(); return code;
        }
        // сравнить регистрирующие органы
        public override bool Equals(object other)
        {
            // сравнить регистрирующие органы
            return (other is Authority) && Equals((Authority)other); 
        }
        // сравнить регистрирующие органы
        public virtual bool Equals(Authority other) 
        { 
            // проверить совпадение ссылок
            if (Object.ReferenceEquals(other, this)) return true; 
            
            // проверить наличие объекта
            if (other == null) return false;

            // проверить число объектов
            if (objects.Count != other.objects.Count) return false; 

            // для всех объектов
            for (int i = 0; i < objects.Count; i++)
            {
                // сравнить объекты
                if (!objects[i].Equals(other.objects[i])) return false; 
            }
            return true; 
        }
	    // получить элемент коллекции
	    public DataObject this[Tag tag] { get { 

            // найти внутренний объект
            foreach (DataObject obj in objects) 
            {
                // проверить совпадение идентификаторов
                if (obj.Tag == tag) return obj;
            }
            return null; 
        }}
        // идентификатор объекта
        public ASN1.ObjectIdentifier ObjectIdentifier { get 
        {
            // найти объект
            DataObject obj = this[new Tag(ASN1.Tag.ObjectIdentifier, ASN1.PC.Primitive)]; 

            // проверить наличие элемента
            if (obj == null) return null; 

            // вернуть значение объекта
            return new ASN1.ObjectIdentifier(
                ASN1.Encodable.Encode(obj.Tag.AsnTag, obj.Tag.PC, obj.Content)
            ); 
        }}
        // код страны и национальные данные
        public BER.CountryIndicator CountryIndicator { get 
        {
            // найти объект
            DataObject obj = this[Tag.CountryIndicator]; 

            // вернуть значение объекта
            return (obj != null) ? new BER.CountryIndicator(obj.Content) : null; 
        }}
        // идентификационный номер эмитента
        public BER.IssuerIndicator IssuerIndicator { get 
        {
            // найти объект
            DataObject obj = this[Tag.IssuerIndicator]; 

            // вернуть значение объекта
            return (obj != null) ? new BER.IssuerIndicator(obj.Content) : null; 
        }}
        // идентификатор приложения 
        public BER.ApplicationIdentifier ApplicationIdentifier { get 
        {
            // найти объект
            DataObject obj = this[Tag.ApplicationIdentifier]; 

            // вернуть значение объекта
            return (obj != null) ? BER.ApplicationIdentifier.Decode(obj.Content) : null; 
        }}
    }
}
