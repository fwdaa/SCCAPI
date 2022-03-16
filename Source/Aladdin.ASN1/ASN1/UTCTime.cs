using System;
using System.IO;
using System.Text; 
using System.Globalization;
using System.Runtime.Serialization;

namespace Aladdin.ASN1
{
	///////////////////////////////////////////////////////////////////////////
	// Дата в диапазоне 1950-2049 
	///////////////////////////////////////////////////////////////////////////
	[Serializable]
	public sealed class UTCTime : VisibleString
	{
        // проверить допустимость типа
        public static new bool IsValidTag(Tag tag) { return tag == Tag.UTCTime; }
    
		// закодировать время
		private static string Encode(DateTime value)
		{
			// получить время по Гринвичу 
			DateTime time = value.ToUniversalTime();

			// проверить корректность даты
			if (time.Year < 1950 || time.Year >= 2050) throw new ArgumentException();

			// извлечь номер года
			int YY = (time.Year >= 2000) ? time.Year - 2000 : time.Year - 1900;

			// закодировать дату
			return String.Format("{0:D2}{1:D2}{2:D2}{3:D2}{4:D2}{5:D2}Z", 
				YY, time.Month, time.Day, time.Hour, time.Minute, time.Second
			);
		}
		// конструктор при сериализации
        private UTCTime(SerializationInfo info, StreamingContext context) 

			// выполнить дополнительные вычисления 
			: base(info, context) { OnDeserialization(this); }

		// дополнительные вычисления при сериализации
		public new void OnDeserialization(object sender)
		{
			string value = base.Value; 

			// извлечь номер года, месяца и дня
			int YY = Int32.Parse(value.Substring(0, 2), NumberStyles.None);
			int MM = Int32.Parse(value.Substring(2, 2), NumberStyles.None);
			int DD = Int32.Parse(value.Substring(4, 2), NumberStyles.None);

			// скорректировать год
			int YYYY = (YY >= 50) ? YY + 1900 : YY + 2000; int ss = 0; int cb = 0;

			// извлечь часы и минуты
			int hh = Int32.Parse(value.Substring(6, 2), NumberStyles.None);
			int mm = Int32.Parse(value.Substring(8, 2), NumberStyles.None);

			// при наличии секунд в строке
			if (value[10] != 'Z' && value[10] != '+' && value[10] != '-')
			{
				// извлечь секунды
				ss = Int32.Parse(value.Substring(10, 2)); cb = 2;
			}
			// создать время по Гринвичу
			time = new DateTime(YYYY, MM, DD, hh, mm, ss, DateTimeKind.Utc);

			// проверить отсутствие часового пояса
			if (value[10 + cb] == 'Z')
			{
				// проверить корректность данных
				if (value.Length != 11 + cb) throw new InvalidDataException(); return;
			}
			// проверить наличие часового пояса
			if (value[10 + cb] != '+' && value[10 + cb] != '-') throw new InvalidDataException();

			// проверить корректность данных
			if (value.Length != 15 + cb) throw new InvalidDataException();

			// извлечь часы и минуты коррекции
			int hhz = Int32.Parse(value.Substring(10 + cb, 2), NumberStyles.None);
			int mmz = Int32.Parse(value.Substring(12 + cb, 2), NumberStyles.None);

			// учесть направление коррекции
			if (value[10 + cb] == '+') { hhz = -hhz; mmz = -mmz; }
			
			// скорректировать время
			time = time.AddHours((double)hhz).AddMinutes((double)mmz);		}

		// конструктор при раскодировании
		public UTCTime(IEncodable encodable) : base(encodable) { OnDeserialization(this); } 

		// конструктор при закодировании
		public UTCTime(DateTime time) : 
			base(Tag.UTCTime, UTCTime.Encode(time)) { this.time = time; } 

		// содержимое объекта
		protected override byte[] DerContent { get 
		{
			// закодировать содержимое объекта
			return Encoding.ASCII.GetBytes(UTCTime.Encode(time)); 
		}}
		// закодированное время
		public new DateTime Value { get { return time; } } [NonSerialized] private DateTime time; 
	}
}
