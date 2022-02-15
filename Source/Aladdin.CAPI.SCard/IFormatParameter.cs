using System;

namespace Aladdin.CAPI.SCard
{
	//////////////////////////////////////////////////////////////////////////////
	// Описание параметра форматирования
	//////////////////////////////////////////////////////////////////////////////
    public interface IFormatParameter
    {
        // проверка корректности параметра
        FormatValidator Validator { get; }

        // порядковый номер и значение параметра 
        int Ordinal { get; } string Value { get; set; }
    }
}
