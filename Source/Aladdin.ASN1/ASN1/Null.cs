﻿using System;
using System.IO;
using System.Runtime.Serialization;

namespace Aladdin.ASN1
{
	///////////////////////////////////////////////////////////////////////////
	// Пустое значение
	///////////////////////////////////////////////////////////////////////////
	[Serializable]
	public sealed class Null : AsnObject
	{
        // проверить допустимость типа
        public static bool IsValidTag(Tag tag) { return tag == Tag.Null; }
    
		// экземпляр объекта
		public static readonly Null Instance = new Null(); 

		// конструктор при сериализации
        private Null(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public Null(IEncodable encodable) : base(encodable)
		{
			// проверить корректность способа кодирования
			if (encodable.PC != PC.Primitive) throw new InvalidDataException();

			// проверить корректность объекта
			if (encodable.Content.Length != 0) throw new InvalidDataException(); 
		}
		// конструктор при закодировании
		public Null() : base(Tag.Null) { }

		// способ кодирования для DER-кодировки
		protected override PC DerPC { get { return PC.Primitive; } }

		// содержимое объекта
		protected override byte[] DerContent { get { return new byte[0]; } } 
	}
}
