using System;
using System.IO;
using System.Collections; 
using System.Collections.Generic; 

namespace Aladdin.ASN1
{
	///////////////////////////////////////////////////////////////////////////
	// Коллекция объектов
	///////////////////////////////////////////////////////////////////////////
	public class Collection : Encodable, IEnumerable<IEncodable> 
	{
		///////////////////////////////////////////////////////////////////////
		// Функции коллекции элементов
		///////////////////////////////////////////////////////////////////////
		internal delegate IEncodable[] CastCallback(ObjectInfo[] info, IEncodable[] encodables);
 
		// конструктор при раскодировании
		internal Collection(IEncodable encodable, ObjectInfo[] info, CastCallback callback) : base(encodable)
		{
			List<IEncodable> list = new List<IEncodable>(); 

			// проверить корректность способа кодирования
			if (encodable.PC != PC.Constructed) throw new InvalidDataException();  

			// задать начальные условия
			int length = encodable.Content.Length; this.info = info;
			
			// для всех внутренних объектов
			for (int cb = 0; length > 0;)
			{
				// раскодировать внутренний объект
				IEncodable item = Encodable.Decode(encodable.Content, cb, length); 

				// перейти на следующий объект
				list.Add(item); cb += item.Encoded.Length; length -= item.Encoded.Length; 
			}
			// преобразовать тип объектов
			values = callback(this.info, list.ToArray()); 
		}
		// конструктор при раскодировании
		internal Collection(IEncodable encodable, ObjectInfo info, CastCallback callback) : base(encodable)
		{
	        // создать список объектов
			List<IEncodable> values = new List<IEncodable>(); 

			// проверить корректность способа кодирования
			if (encodable.PC != PC.Constructed) throw new InvalidDataException();  
			
			// для всех внутренних объектов
			for (int cb = 0, length = encodable.Content.Length; length > 0;)
			{
				// раскодировать внутренний объект
				IEncodable item = Encodable.Decode(encodable.Content, cb, length); 

	            // проверить совпадение типа
	            if (!info.IsValidTag(item.Tag)) throw new InvalidDataException(); 

	            // раскодировать объект
	            values.Add(info.Decode(item, true));

				// перейти на следующий объект
				cb += item.Encoded.Length; length -= item.Encoded.Length; 
			}

			// выделить память для информации о типе
			this.info = new ObjectInfo[values.Count]; this.values = values.ToArray(); 
				
			// сохранить информацию о типе
			for (int i = 0; i < this.info.Length; i++) this.info[i] = info;  
		}
		// конструктор при закодировании
		internal Collection(Tag tag, ObjectInfo[] info, params IEncodable[] values) : base(tag, PC.Constructed) 
		{
			// проверить совпадение числа элементов
			if (info.Length != values.Length) throw new ArgumentException(); 

			// сохранить элементы с информацией о типе
			this.info = info; this.values = new IEncodable[values.Length]; 
  
			// для всех элементов
			for (int i = 0; i < values.Length; i++)
			{
				// при наличии элемента
				if (values[i] != null)
				{
					// раскодировать элемент
					this.values[i] = info[i].Factory.Decode(values[i]);
				}
				// при допустимости отсутствия элемента
				else if ((info[i].Cast & Cast.O) != 0)
				{
					// установить значение по умолчанию
					this.values[i] = info[i].Value;
				}
				// при ошибке выбросить исключение
				else throw new ArgumentException(); 
			}
		}
		// конструктор при закодировании
		internal Collection(Tag tag, ObjectInfo info, params IEncodable[] values) : base(tag, PC.Constructed) 
		{
			// сохранить элементы коллекции
			this.values = new IEncodable[values.Length]; this.info = new ObjectInfo[values.Length]; 
				
			// сохранить информацию о типе
			for (int i = 0; i < this.info.Length; i++) this.info[i] = info;  

			// для всех элементов
			for (int i = 0; i < values.Length; i++)
			{
				// проверить наличие элемента
				if (values[i] == null) throw new ArgumentException();

				// раскодировать элемент
				this.values[i] = info.Factory.Decode(values[i]); 
			}
		}
		// содержимое объекта
		protected override byte[] GetContent() 
		{
 			// выделить память для кодирования объектов
			byte[][] encoded = new byte[values.Length][]; int cb = 0;  

			// для каждого внутреннего объекта
			for (int i = 0; i < values.Length; i++)
			{
				// проверить необходимость кодирования
				if (values[i] == null) continue;
 
				// для необязательного элемента
				if ((info[i].Cast & Cast.O) != 0)
				{
					// проверить совпадение с элементом по умолчанию
					if (values[i].Equals(info[i].Value)) continue; 
				}
				// при явном приведении типа
				if ((info[i].Cast & Cast.E) != 0)
				{
					// выполнить явное преобразование
					encoded[i] = Explicit.Encode(info[i].Tag, values[i]).Encoded;
				}
				// при неявном переопределении класса и типа
				else if (info[i].Tag != Tag.Any)
				{
					// выполнить неявное преобразование
					encoded[i] = Encodable.Encode(info[i].Tag, 
						values[i].PC, values[i].Content).Encoded; 
				}
				// закодировать объект
				else encoded[i] = values[i].Encoded;

				// увеличить общий размер объекта
				cb += encoded[i].Length; 
 			}
			// выделить память для содержимого
			byte[] content = new byte[cb]; cb = 0; ArrangeEncodings(ref encoded);

			// для каждого внутреннего объекта
			for (int i = 0; i < values.Length; i++)
			{
				// проверить необходимость кодирования
				if (encoded[i] == null) continue; 

				// скопировать закодированное представление
				Array.Copy(encoded[i], 0, content, cb, encoded[i].Length);

				// перейти на следующий объект
				cb += encoded[i].Length; 
			}
			return content; 
		}
		// отсортировать представления
		protected virtual void ArrangeEncodings(ref byte[][] encoded) {} 

		// перечислитель объектов
		public IEnumerator<IEncodable> GetEnumerator() 
		{ 
			// перечислитель объектов
			return new List<IEncodable>(values).GetEnumerator(); 
		}
		// перечислитель объектов
		IEnumerator IEnumerable.GetEnumerator() { return values.GetEnumerator(); }

		// получить элемент коллекции
		public IEncodable this[int i] { get { return values[i]; } 

			// установить элемент коллекции
			protected set { values[i] = value; } 
		}
		// размер коллекции
		public int Length { get { return values.Length; } } 

		// коллекция элементов
		private IEncodable[] values; private ObjectInfo[] info;
	}
}
