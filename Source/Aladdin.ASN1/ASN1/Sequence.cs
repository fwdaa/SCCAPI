using System;
using System.IO;
using System.Collections.Generic; 
using System.Runtime.Serialization;

namespace Aladdin.ASN1
{
	///////////////////////////////////////////////////////////////////////////
	// Последовательность объектов
	///////////////////////////////////////////////////////////////////////////
	[Serializable]
	public class Sequence : Collection
	{
        // проверить допустимость типа
        public static bool IsValidTag(Tag tag) { return tag == Tag.Sequence; }
    
		// проверить корректность объекта
		public static void Validate(Sequence encodable, bool encode, IObjectFactory factory, int min, int max) 
		{
			// проверить корректность
			Validate(encodable, encode, factory); 

			// проверить корректность
			if (encodable == null && encodable.Length < min) 
            {
			    // выбросить исключение 
			    if (encode) throw new ArgumentException(); else throw new InvalidDataException(); 
            }
			// проверить корректность
			if (encodable == null && encodable.Length > max) 
            {
			    // выбросить исключение 
			    if (encode) throw new ArgumentException(); else throw new InvalidDataException(); 
            }
		} 
		// проверить корректность объекта
		public static void Validate(Sequence encodable, bool encode, int min, int max) 
		{
			// проверить корректность
			if (encodable == null && encodable.Length < min) 
            {
			    // выбросить исключение 
			    if (encode) throw new ArgumentException(); else throw new InvalidDataException(); 
            }
			// проверить корректность
			if (encodable == null && encodable.Length > max) 
            {
			    // выбросить исключение 
			    if (encode) throw new ArgumentException(); else throw new InvalidDataException(); 
            }
		} 
		// проверить корректность объекта
		public static void Validate(Sequence encodable, bool encode, IObjectFactory factory, int min) 
		{
			// проверить корректность
			Validate(encodable, encode, factory); 

			// проверить корректность
			if (encodable == null && encodable.Length < min) 
            {
			    // выбросить исключение 
			    if (encode) throw new ArgumentException(); else throw new InvalidDataException(); 
            }
		} 
		// проверить корректность объекта
		public static void Validate(Sequence encodable, bool encode, int min) 
		{
			// проверить корректность
			if (encodable == null && encodable.Length < min) 
            {
			    // выбросить исключение 
			    if (encode) throw new ArgumentException(); else throw new InvalidDataException(); 
            }
		} 
		// проверить корректность объекта
		public static void Validate(Sequence encodable, bool encode, IObjectFactory factory) 
		{
			// проверить корректность каждого элемента
			if (encodable != null) foreach (IEncodable obj in encodable) factory.Validate(obj, encode); 
		} 
		// информация об отдельном элементе	
		private static ObjectInfo GetInfo(IObjectFactory factory)
		{
			// атрибуты элемента в последовательности
			return new ObjectInfo(factory, ASN1.Cast.N, Tag.Any, null); 
		}
		// конструктор при сериализации
        protected Sequence(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public Sequence(IObjectFactory factory, IEncodable encodable) 
			: base(encodable, GetInfo(factory)) {}

		// конструктор при раскодировании
		public Sequence(IEncodable encodable) 
			: base(encodable, GetInfo(ImplicitCreator.Factory)) {}

		// конструктор при раскодировании
		protected Sequence(IEncodable encodable, ObjectInfo[] info) 
			: base(encodable, info, Cast) {}

		// конструктор при закодировании
		public Sequence(IObjectFactory factory, params IEncodable[] values) 
			: base(Tag.Sequence, GetInfo(factory), values) {}

		// конструктор при закодировании
		protected Sequence(ObjectInfo[] info, params IEncodable[] values) 
			: base(Tag.Sequence, info, values) {}

		// приведение типа объектов
		private static IEncodable[] Cast(ObjectInfo[] info, IEncodable[] encodables)
		{
			// выделить память для преобразованных объектов
			IEncodable[] values = new IEncodable[info.Length]; int pos = 0;  

			// для всех раскодированных объектов
			for (int i = 0; i < encodables.Length; i++, pos++)
			{
				// для всех элементов
				for (; pos < info.Length; pos++)
				{
					// проверить совпадение типа
					if (info[pos].IsValidTag(encodables[i].Tag)) break; 

					// проверить необязательность элемента
					if ((info[pos].Cast & ASN1.Cast.O) == 0)
					{
						// при ошибке выбросить исключение
						throw new InvalidDataException();    
					}
					// установить значение элемента по умолчанию
					values[pos] = info[pos].Value; 
				}
				// проверить корректность данных
				if (pos == info.Length) return values;

				// раскодировать объект
				values[pos] = info[pos].Decode(encodables[i], true);
			}
			// для всех непрочитанных элементов
			for (int i = pos; i < info.Length; i++)
			{
				// проверить необязательность элемента
				if ((info[i].Cast & ASN1.Cast.O) == 0)
				{
					// при ошибке выбросить исключение
					throw new InvalidDataException();    
				}
				// установить значение элемента по умолчанию
				values[i] = info[i].Value;     
			}
			return values; 
		}
	}
	///////////////////////////////////////////////////////////////////////////
	// Последовательность объектов произвольного типа
	///////////////////////////////////////////////////////////////////////////
	[Serializable]
	public class Sequence<T> : Sequence, IEnumerable<T> where T : IEncodable
	{
		// конструктор при сериализации
        protected Sequence(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public Sequence(IObjectFactory<T> factory, IEncodable encodable) : 
			base(factory, encodable) {}

		// конструктор при раскодировании
		public Sequence(IObjectFactory factory, IEncodable encodable) : 
			base((IObjectFactory<T>)factory, encodable) {}

		// конструктор при раскодировании
		public Sequence(IEncodable encodable) : this(new ObjectCreator<T>().Factory(), encodable) {}

		// конструктор при закодировании
		public Sequence(IObjectFactory<T> factory, params T[] values) : 
			base(factory, Arrays.Convert<IEncodable, T>(values)) {} 

		// конструктор при закодировании
		public Sequence(params T[] values) : this(new ObjectCreator<T>().Factory(), values) {} 

		// элемент коллекции
		public new T this[int i] { get { return (T)base[i]; } 
		
			// установить элемент коллекции
			protected set { base[i] = value; } 
		}
		// перечислитель объектов
		IEnumerator<T> IEnumerable<T>.GetEnumerator() 
		{ 
			// вернуть перечислитель объектов
			return new Enumerator<T>(base.GetEnumerator()); 
		}
	}
}
