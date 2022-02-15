using System;
using System.IO;

namespace Aladdin.ASN1
{
	///////////////////////////////////////////////////////////////////////////
	// Объект с явным приведением типа от произвольного типа
	///////////////////////////////////////////////////////////////////////////
	public class Explicit : Encodable
	{
		// закодировать объект
		public static IEncodable Encode(Tag tag, IEncodable encodable)
		{
			// закодировать объект
			return Encodable.Encode(tag, PC.Constructed, encodable.Encoded); 
		}
		// конструктор при раскодировании
		public Explicit(IObjectFactory factory, IEncodable encodable) : base(encodable) 
		{
			// проверить корректность способа кодирования
			if (encodable.PC != PC.Constructed) throw new InvalidDataException();

			// раскодировать внутренний объект
			value = factory.Decode(Encodable.Decode(encodable.Content)); 

			// проверить наличие только одного объекта
			if (value.Encoded.Length != encodable.Content.Length)
			{
				// при ошибке выбросить исключение
				throw new InvalidDataException();
			}
		}
		// конструктор при закодировании
		public Explicit(IObjectFactory factory, Tag tag, IEncodable value) : base(tag, PC.Constructed) 
		{
			// проверить корректность объекта
			this.value = factory.Decode(value); 
		} 
		// содержимое объекта
		protected override byte[] GetContent() { return value.Encoded; }

		// исходный объект
		public IEncodable Inner { get { return value; } } protected IEncodable value; 
	}
	///////////////////////////////////////////////////////////////////////////
	// Объект с явным приведением типа от указанного типа
	///////////////////////////////////////////////////////////////////////////
	public class Explicit<T> : Explicit where T : IEncodable
	{
		// конструктор при раскодировании
		public Explicit(IObjectFactory<T> factory, IEncodable encodable) : base(factory, encodable) 
		{
			// раскодировать внутренний объект
			value = factory.Decode(value); 
		}
		// конструктор при раскодировании
		public Explicit(IEncodable encodable) : this(new ObjectCreator<T>().Factory(), encodable) {}

		// конструктор при закодировании
		public Explicit(IObjectFactory<T> factory, Tag tag, T value) : base(factory, tag, value) {}

		// конструктор при закодировании
		public Explicit(Tag tag, T value) : this(new ObjectCreator<T>().Factory(), tag, value) {} 

		// исходный объект
		public new T Inner { get { return (T)base.Inner; } }
	}
}
