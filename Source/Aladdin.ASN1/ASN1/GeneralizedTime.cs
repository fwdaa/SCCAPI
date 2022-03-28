using System;
using System.IO;
using System.Text;
using System.Globalization;
using System.Runtime.Serialization;

namespace Aladdin.ASN1
{
	///////////////////////////////////////////////////////////////////////////
	// Произвольная дата
	///////////////////////////////////////////////////////////////////////////
	[Serializable]
	public sealed class GeneralizedTime : VisibleString
	{
        // проверить допустимость типа
        public static new bool IsValidTag(Tag tag) { return tag == Tag.GeneralizedTime; }
    
		// закодировать время
		private static string Encode(DateTime value, string frac)
		{
			// закодировать дату
			string encoded = GeneralizedTime.Encode(value);

			// добавить дробную часть секунд
			return (frac.Length != 0) ? String.Format("{0}.{1}", encoded, frac) : encoded;
		}
		// закодировать время
		private static string Encode(DateTime value)
		{
			// получить время по Гринвичу 
			DateTime time = value.ToUniversalTime();

			// закодировать дату
			return String.Format("{0:D4}{1:D2}{2:D2}{3:D2}{4:D2}{5:D2}Z", 
				time.Year, time.Month, time.Day, time.Hour, time.Minute, time.Second
			);
		}
		// конструктор при сериализации
        private GeneralizedTime(SerializationInfo info, StreamingContext context) 

			// инициализировать объект
			: base(info, context) { Init(); } private void Init()
		{
			string value = base.Value; frac = String.Empty; 

			// указать допустимость точки как разделителя
			IFormatProvider provider = NumberFormatInfo.InvariantInfo; 

			// извлечь номер года, месяца, дня и часы
			int YYYY = Int32.Parse(value.Substring(0, 4), NumberStyles.None);
			int MM   = Int32.Parse(value.Substring(4, 2), NumberStyles.None);
			int DD   = Int32.Parse(value.Substring(6, 2), NumberStyles.None);
			int hh   = Int32.Parse(value.Substring(8, 2), NumberStyles.None);

			// создать локальное время
			time = new DateTime(YYYY, MM, DD, hh, 0, 0, DateTimeKind.Local);

			// проверить необходимость дальнейших действий
			if (value.Length == 10) { time = time.ToUniversalTime(); return; } int cb = 0;

			// наличие дробной части в часах не поддерживается 
			if (value[10] == '.' || value[10] == ',') throw new InvalidDataException(); 

			// при наличии минут
			if (value[10] != 'Z' && value[10] != '+' && value[10] != '-')
			{
				// прочитать минуты
				time = time.AddMinutes(Int32.Parse(value.Substring(10, 2), NumberStyles.None));

				// проверить необходимость дальнейших действий
				if (value.Length == 12) { time = time.ToUniversalTime(); return; } cb = 2; 

				// наличие дробной части в минутах не поддерживается 
				if (value[12] == '.' || value[12] == ',') throw new InvalidDataException(); 

				// при наличии секунд
				if (value[12] != 'Z' && value[12] != '+' && value[12] != '-')
				{
					// прочитать секунды
					time = time.AddSeconds(Int32.Parse(value.Substring(12, 2), NumberStyles.None));

					// проверить необходимость дальнейших действий
					if (value.Length == 14) { time = time.ToUniversalTime(); return; } cb = 4; 

					// при наличии дробной части в секундах
					if (value[14] == '.' || value[14] == ',')
					{
						// проверить корректность данных
						if (!Char.IsDigit(value[15])) throw new InvalidDataException();

						// определить число цифр в дробной части
						int i = 1; while (15 + i < value.Length && Char.IsDigit(value[15 + i])) i++;

						// проигнорировать незначимые нули
						cb = 5 + i; while (value[15 + i] == '0') i--; 
			 
						// при наличии дробной части
						if (i > 0) { frac = "." + value.Substring(15, i);
			 
							// указать допустимость точки как разделителя
							NumberStyles styles = NumberStyles.AllowDecimalPoint; 

							// добавить дробную часть ко времени
							time = time.AddSeconds(Double.Parse(frac, styles, provider)); 
						}
					}
				}
			}
			// проверить необходимость дальнейших действий
			if (value.Length == 10 + cb) { time = time.ToUniversalTime(); return; }  

			// проверить указание времени по Гринвичу
			if (value[10 + cb] == 'Z')
			{
				// проверить корректность данных
				if (value.Length != 11 + cb) throw new InvalidDataException(); 

				// вернуть время по Гринвичу
				time = DateTime.SpecifyKind(time, DateTimeKind.Utc); return;  
			}
			// проверить наличие часового пояса
			if (value[10 + cb] != '+' && value[10 + cb] != '-') throw new InvalidDataException();

			// проверить размер строки
			if (value.Length != 15 + cb) throw new InvalidDataException();

			// извлечь часы и минуты коррекции
			int hhz = Int32.Parse(value.Substring(11 + cb, 2), NumberStyles.None);
			int mmz = Int32.Parse(value.Substring(13 + cb, 2), NumberStyles.None);

			// учесть направление коррекции
			if (value[10 + cb] == '+') { hhz = -hhz; mmz = -mmz; }

			// скорректировать время
			time = time.AddHours((double)hhz).AddMinutes((double)mmz);
		}
		// конструктор при раскодировании
		public GeneralizedTime(IEncodable encodable) : base(encodable) { Init(); }

		// конструктор при закодировании
		public GeneralizedTime(DateTime time) : 
			base(Tag.GeneralizedTime, GeneralizedTime.Encode(time)) 
		{
			// сохранить время
			this.time = time; frac = String.Empty; 
		}
		// содержимое объекта
		protected override byte[] DerContent { get 
		{
			// закодировать содержимое объекта
			return Encoding.ASCII.GetBytes(GeneralizedTime.Encode(time, frac)); 
		}}
		// закодированное время
		public new DateTime Value { get { return time; } } 
		
		// время и дробная часть секунд
		[NonSerialized] private DateTime time; [NonSerialized] private string frac; 
	}
}
