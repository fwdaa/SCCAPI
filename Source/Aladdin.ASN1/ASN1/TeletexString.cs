﻿using System;
using System.IO;
using System.Text;
using System.Runtime.Serialization;

namespace Aladdin.ASN1
{
	//////////////////////////////////////////////////////////////////////////////
	// Строка символов Teletex
	//////////////////////////////////////////////////////////////////////////////
	[Serializable]
	public sealed class TeletexString : OctetString
	{
        // проверить допустимость типа
        public static new bool IsValidTag(Tag tag) { return tag == Tag.TeletexString; }
    
		// проверить корректность объекта
		public static void Validate(TeletexString encodable, bool encode, int min, int max) 
		{
			// проверить корректность
			if (encodable != null && encodable.Value.Length < min) 
            {
			    // выбросить исключение 
			    if (encode) throw new ArgumentException(); else throw new InvalidDataException(); 
            }
			// проверить корректность
			if (encodable != null && encodable.Value.Length > max) 
            {
			    // выбросить исключение 
			    if (encode) throw new ArgumentException(); else throw new InvalidDataException(); 
            }
		} 
		// проверить корректность объекта
		public static void Validate(TeletexString encodable, bool encode, int min) 
		{
			// проверить корректность
			if (encodable != null && encodable.Value.Length < min) 
            {
			    // выбросить исключение 
			    if (encode) throw new ArgumentException(); else throw new InvalidDataException(); 
            }
		} 
		// конструктор при сериализации
        private TeletexString(SerializationInfo info, StreamingContext context) 

			// инициализировать объект
			: base(info, context) { Init(); } private void Init()
		{
			// раскодировать строку
			str = Encoding.Default.GetString(Content); 
		}
		// конструктор при раскодировании
		public TeletexString(IEncodable encodable) : base(encodable) { Init(); }

		// конструктор при закодировании
		public TeletexString(string value) : base(Tag.TeletexString, 
			
			// закодировать строку
			Encoding.Default.GetBytes(value)) { str = value; } 

		// строка символов
		public new string Value { get { return str; } } [NonSerialized] private string str; 
	}
}
