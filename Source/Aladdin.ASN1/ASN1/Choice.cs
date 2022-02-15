using System;
using System.IO;

namespace Aladdin.ASN1
{
	///////////////////////////////////////////////////////////////////////////
	// Выбор из множества объектов
	///////////////////////////////////////////////////////////////////////////
	public class Choice : IObjectFactory 
	{
		// конструктор при раскодировании
		public Choice(ObjectInfo[] info) { this.info = info; } private ObjectInfo[] info; 

		// проверить допустимость типа
		public bool IsValidTag(Tag tag)
		{
			// для всех возможных альтернатив
			foreach (ObjectInfo item in info)
			{
				// проверить совпадение типа
				if (item.IsValidTag(tag)) return true; 
			}
			return false; 
		}
		// проверить корректность объекта
		public void Validate(IEncodable encodable, bool encode)
		{
			// для всех возможных альтернатив
			foreach (ObjectInfo item in info)
			{
				// проверить совпадение типа
				if (!item.IsValidTag(encodable.Tag)) continue; 

				// проверить корректность объекта
				item.Validate(encodable, encode); return; 
			}
		    // выбросить исключение 
		    if (encode) throw new ArgumentException(); else throw new InvalidDataException(); 
		}
		// получить информацию кодирования
		public ObjectInfo GetEncodableInfo(IEncodable encodable) 
		{
			// для всех возможных альтернатив
			foreach (ObjectInfo item in info)
			{
				// проверить совпадение типа
				if (item.IsValidTag(encodable.Tag)) return item;
			}
			// ошибка - некорректный объект
			throw new InvalidDataException(); 
		}
        // раскодировать объект
        public IEncodable Decode(IEncodable encodable) 
        { 
			// для всех возможных альтернатив
			foreach (ObjectInfo item in info)
			{
				// проверить совпадение типа
				if (!item.IsValidTag(encodable.Tag)) continue; 

				// раскодировать объект
				return item.Decode(encodable, false);
			}
			// ошибка - некорректный объект
			throw new InvalidDataException(); 
        }
	}
}
