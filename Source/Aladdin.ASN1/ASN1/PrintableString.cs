﻿using System;
using System.IO;
using System.Text;

namespace Aladdin.ASN1
{
	///////////////////////////////////////////////////////////////////////////
	// Строка печатаемых символов
	///////////////////////////////////////////////////////////////////////////
	public class PrintableString : OctetString	
	{
        // проверить допустимость типа
        public static new bool IsValidTag(Tag tag) { return tag == Tag.PrintableString; }
    
		// проверить корректность объекта
		public static void Validate(PrintableString encodable, bool encode, int min, int max) 
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
		public static void Validate(PrintableString encodable, bool encode, int min) 
		{
			// проверить корректность
			if (encodable != null && encodable.Value.Length < min) 
            {
			    // выбросить исключение 
			    if (encode) throw new ArgumentException(); else throw new InvalidDataException(); 
            }
		} 
		// конструктор при раскодировании
		public PrintableString(IEncodable encodable) : base(encodable) 
		{ 
			// раскодировать строку
			str = Encoding.ASCII.GetString(Content); 
		}
		// конструктор при закодировании
		public PrintableString(string value) : base(Tag.PrintableString, 
			
			// закодировать строку
			Encoding.ASCII.GetBytes(value)) { str = value; } 

		// строка символов
		public new string Value { get { return str; } } private string str; 
	}
}