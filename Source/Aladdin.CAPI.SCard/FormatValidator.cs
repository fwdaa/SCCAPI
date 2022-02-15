using System;
using System.Text;

namespace Aladdin.CAPI.SCard
{
	//////////////////////////////////////////////////////////////////////////////
    // Проверка корректности параметра
	//////////////////////////////////////////////////////////////////////////////
    public abstract class FormatValidator 
    { 
        // проверить корректность параметра
        public virtual bool Check(object value) { return true; } 

	    //////////////////////////////////////////////////////////////////////////
        // Проверка на максимальное и минимальное значение
	    //////////////////////////////////////////////////////////////////////////
        public class Range : FormatValidator
        {
            // конструктор
            public Range(int min, int max) { Min = min; Max = max; }

            // проверить корректность параметра
            public override bool Check(object value)
            {
                // преобразовать тип объекта
                int val = Convert.ToInt32(value); 

                // проверить вхождение в диапазон
                return Min <= val && val <= Max; 
            }
            // минимальное и максимальное значение
            public readonly int Min; public readonly int Max;
        }
	    //////////////////////////////////////////////////////////////////////////
        // Проверка на максимальное и минимальное значение длины
	    //////////////////////////////////////////////////////////////////////////
        public class Length : FormatValidator
        {
		    // признак обязательного значения
		    private bool required; 

            // конструктор
            public Length(int min, int max, bool required) 

			    // сохранить переданные параметры 
			    { Min = min; Max = max; this.required = required; }

            // конструктор
            public Length(int min, int max) 

			    // сохранить переданные параметры 
			    { Min = min; Max = max; required = true; }

            // проверить корректность параметра
            public override bool Check(object value)
            {
			    // проверить допустимость отсутствии значения
			    if (value == null) return !required; 

                // преобразовать тип объекта
                byte[] val = Encoding.UTF8.GetBytes(Convert.ToString(value)); 

                // проверить вхождение в диапазон
                return Min <= val.Length && val.Length <= Max; 
            }
            // минимальное и максимальное значение
            public readonly int Min; public readonly int Max;
        }
    }
}
