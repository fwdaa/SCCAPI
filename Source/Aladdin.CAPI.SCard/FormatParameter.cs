using System;

namespace Aladdin.CAPI.SCard
{
	//////////////////////////////////////////////////////////////////////////////
	// Описание параметра форматирования
	//////////////////////////////////////////////////////////////////////////////
    public class FormatParameter<T> : IFormatParameter
    {
        // значение и функция проверки корректности
        private T value; private int ordinal; private FormatValidator validator; 

        // конструктор
        public FormatParameter(int ordinal, T value, FormatValidator validator)
        {
            // сохранить переданные параметры
            this.validator = validator; Value = value; this.ordinal = ordinal; 
        }
        // конструктор
        public FormatParameter(int ordinal, T value)
        {
            // сохранить переданные параметры
            this.validator = null; Value = value; this.ordinal = ordinal; 
        }
        // проверка корректности параметра
        public FormatValidator Validator { get { return validator; }}

        // порядковый номер
        public int Ordinal { get { return ordinal; }}

        // значение параметра 
        public T Value { get { return value; } set 
        { 
            // проверить корректность значения
            if (validator != null && !validator.Check(value))
            {
                // при ошибке выбросить исключение
                throw new ArgumentOutOfRangeException(); 
            }
            this.value = value;
        }}
        // значение параметра 
        string IFormatParameter.Value 
        { 
            // получить значение параметра
            get { return value.ToString(); } 
            set { 
                // раскодировать значение
                T obj = FromString(value); 

                // проверить корректность значения
                if (validator != null && !validator.Check(obj))
                {
                    // при ошибке выбросить исключение
                    throw new ArgumentOutOfRangeException(); 
                }
                this.value = (T)obj;
            }
        }
        // описание параметра в виде строки
        public override string ToString() { return value.ToString(); }

        // раскодировать значение параметра
        private T FromString(string value)
        {
            // проверить наличие значения
            if (String.IsNullOrEmpty(value) && typeof(T).IsValueType)
            {
                // при ошибке выбросить исключение
                throw new ArgumentOutOfRangeException(); 
            }
            // раскодировать значение
            if (typeof(T).IsEnum) return (T)Enum.Parse(typeof(T), value);

            // раскодировать значение
            if (typeof(T).Equals(typeof(bool  ))) return (T)(object)Convert.ToBoolean(value); 
            if (typeof(T).Equals(typeof(char  ))) return (T)(object)Convert.ToChar   (value); 
            if (typeof(T).Equals(typeof(byte  ))) return (T)(object)Convert.ToByte   (value); 
            if (typeof(T).Equals(typeof(short ))) return (T)(object)Convert.ToInt16  (value); 
            if (typeof(T).Equals(typeof(ushort))) return (T)(object)Convert.ToUInt16 (value); 
            if (typeof(T).Equals(typeof(int   ))) return (T)(object)Convert.ToInt32  (value); 
            if (typeof(T).Equals(typeof(uint  ))) return (T)(object)Convert.ToUInt32 (value); 
            if (typeof(T).Equals(typeof(long  ))) return (T)(object)Convert.ToInt64  (value); 
            if (typeof(T).Equals(typeof(ulong ))) return (T)(object)Convert.ToUInt64 (value); 
            if (typeof(T).Equals(typeof(float ))) return (T)(object)Convert.ToSingle (value); 
            if (typeof(T).Equals(typeof(double))) return (T)(object)Convert.ToDouble (value); 
            if (typeof(T).Equals(typeof(string))) return (T)(object)Convert.ToString (value); 

            // при ошибке выбросить исключение
            throw new NotSupportedException(); 
        }
    }
}
