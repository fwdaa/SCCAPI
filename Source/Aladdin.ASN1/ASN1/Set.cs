using System;
using System.IO;
using System.Collections; 
using System.Collections.Generic; 

namespace Aladdin.ASN1
{
	///////////////////////////////////////////////////////////////////////////
	// Множество объектов
	///////////////////////////////////////////////////////////////////////////
	public class Set : Collection
	{
        // проверить допустимость типа
        public static bool IsValidTag(Tag tag) { return tag == Tag.Set; }
    
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
			// атрибуты элемента в множестве
			return new ObjectInfo(factory, ASN1.Cast.N, Tag.Any, null); 
		}
		// конструктор при раскодировании
		public Set(IObjectFactory factory, IEncodable encodable) : 
			base(encodable, GetInfo(factory), Cast) {}

		// конструктор при раскодировании
		public Set(IEncodable encodable) : 
			base(encodable, GetInfo(ImplicitCreator.Factory), Cast) {}

		// конструктор при раскодировании
		protected Set(IEncodable encodable, ObjectInfo[] info) : 
			base(encodable, info, Cast) {}

		// конструктор при закодировании
		public Set(IObjectFactory factory, params IEncodable[] values) : 
			base(Tag.Set, GetInfo(factory), values) {}

		// конструктор при закодировании
		protected Set(ObjectInfo[] info, params IEncodable[] values) : 
			base(Tag.Set, info, values) {}

		// приведение типа объектов
		private static IEncodable[] Cast(ObjectInfo[] info, IEncodable[] encodables)
		{
			// выделить память для преобразованных объектов
			IEncodable[] values = new IEncodable[info.Length];   

			// для всех раскодированных объектов
			for (int i = 0; i < encodables.Length; i++)
			{
				// для всех элементов
				int pos; for (pos = 0; pos < info.Length; pos++)
				{
					// проверить занятие позиции
					if (values[pos] != null) continue; 

					// проверить совпадение типа
					if (info[pos].IsValidTag(encodables[i].Tag)) break; 
				}
				// проверить корректность данных
				if (pos == info.Length) continue;

				// раскодировать объект
				values[pos] = info[pos].Decode(encodables[i], true);
			}
			// для всех непрочитанных элементов
			for (int i = 0; i < values.Length; i++)
			{
				// проверить наличие элемента
				if (values[i] != null) continue; 
					
				// проверить допустимость отсутствия элемента
				if ((info[i].Cast & ASN1.Cast.O) == 0) 
				{
 					// при ошибке выбросить исключение
					throw new InvalidDataException(); 
				}
				// установить значение по умолчанию
				values[i] = info[i].Value;  
			}
			return values; 
		}
		// отсортировать представления
		protected override void ArrangeEncodings(ref byte[][] encoded) 
		{
			// отсортировать представления
			Array.Sort(encoded, Arrays.Compare<Byte>); 
		} 
	}
	///////////////////////////////////////////////////////////////////////////
	// Множество объектов произвольного типа
	///////////////////////////////////////////////////////////////////////////
	public class Set<T> : Set, IEnumerable<T> where T : IEncodable
	{
		// конструктор при раскодировании
		public Set(IObjectFactory<T> factory, IEncodable encodable) : 
			base(factory, encodable) {}

		// конструктор при раскодировании
		public Set(IObjectFactory factory, IEncodable encodable) : 
			base((IObjectFactory<T>)factory, encodable) {}

		// конструктор при раскодировании
		public Set(IEncodable encodable) : this(new ObjectCreator<T>().Factory(), encodable) {}

		// конструктор при закодировании
		public Set(IObjectFactory<T> factory, params T[] values) : 
			base(factory, Arrays.Convert<IEncodable, T>(values)) {} 

		// конструктор при закодировании
		public Set(params T[] values) : this(new ObjectCreator<T>().Factory(), values) {} 

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
