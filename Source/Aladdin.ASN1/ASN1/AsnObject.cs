﻿using System;

namespace Aladdin.ASN1
{
	///////////////////////////////////////////////////////////////////////////
	// Известный объект ASN.1
	///////////////////////////////////////////////////////////////////////////
	public abstract class AsnObject : IEncodable
	{
		private Tag			tag;	// тип объекта
		private IEncodable	ber;	// закодированное BER-представление
		private IEncodable	der;	// закодированное DER-представление

		// конструктор при раскодировании
		protected AsnObject(IEncodable encodable)
		{
			this.tag = encodable.Tag;	// тип объекта
			this.ber = encodable;		// закодированное BER-представление
			this.der = null;			// закодированное DER-представление
		}
		// конструктор при закодировании
		protected AsnObject(Tag tag)
		{
			this.tag = tag;				// тип объекта
			this.ber = null;			// закодированное BER-представление
			this.der = null;			// закодированное DER-представление
		}
		// атрибуты объекта
		public Tag    Tag     { get { return BerEncodable.Tag;	   }}
		public PC     PC      { get { return BerEncodable.PC;	   }}
		public byte[] Content { get { return BerEncodable.Content; }}
		public byte[] Encoded { get { return BerEncodable.Encoded; }}

		// способ кодирования и содержимое объекта
		protected abstract PC	  DerPC			{ get; }
		protected abstract byte[] DerContent	{ get; }

		private IEncodable BerEncodable { get 
		{
			// вернуть закодированное BER-представление
			if (ber == null) ber = DerEncodable; return ber; 
		}}
		public virtual IEncodable DerEncodable { get
		{
			// вернуть закодированное DER-представление
			if (der == null) der = Encodable.Encode(tag, DerPC, DerContent); return der;  
		}}
		/////////////////////////////////////////////////////////////////////////////
		// Сравнить два объекта
		/////////////////////////////////////////////////////////////////////////////
		public override int GetHashCode()
		{
			// получить хэш-код объекта
			return DerEncodable.Encoded[0].GetHashCode(); 
		}
		public override bool Equals(object obj)
		{
			// сравнить два объекта
			return (obj is IEncodable) ? Equals((IEncodable)obj) : false;  
		}
		public bool Equals(IEncodable obj)
		{
			// выполнить тривиальные проверки
			if (obj == null) return false; if ((object)this == (object)obj) return true;  
				
			// сравнить два объекта
			if (obj is AsnObject) return Equals((AsnObject)obj); 

			// сравнить два объекта
			return Arrays.Equals(DerEncodable.Encoded, obj.Encoded);  
		}
		public bool Equals(AsnObject obj)
		{
			// выполнить тривиальные проверки
			if (obj == null) return false; if ((object)this == (object)obj) return true;  
				
			// сравнить два объекта
			return Arrays.Equals(DerEncodable.Encoded, obj.DerEncodable.Encoded);  
		}
	}
}