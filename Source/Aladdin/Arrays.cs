using System;
using System.Globalization;
using System.IO;

namespace Aladdin
{
    public static class Arrays
    {
		/////////////////////////////////////////////////////////////////////////////
		// Сравнение массивов на равенство
		/////////////////////////////////////////////////////////////////////////////
		public static bool Equals<T>(T[] arr1, int arrOff1, T[] arr2, int arrOff2, int arrLen)
		{
			// для каждого элемента массива 
			for (int i = 0; i < arrLen; i++)
			{
				// сравнить элементы массива
				if (!arr1[arrOff1 + i].Equals(arr2[arrOff2 + i])) return false;
			}
			return true;
		}
		public static bool Equals<T>(T[] arr1, T[] arr2)
		{
			// выполнить тривиальные проверки
			if (arr1 == null && arr2 == null) return true; 
			if (arr1 == null && arr2 != null) return false; 
			if (arr1 != null && arr2 == null) return false; 

			// проверить размер массивов
			if (arr1.Length != arr2.Length) return false;

			// сравнить массивы на равенство
			return Equals<T>(arr1, 0, arr2, 0, arr1.Length);
		}
		/////////////////////////////////////////////////////////////////////////////
		// Сравнение массивов
		/////////////////////////////////////////////////////////////////////////////
		public static int Compare<T>(
            T[] arr1, int arrOff1, int arrLen1,
			T[] arr2, int arrOff2, int arrLen2) where T : IComparable<T>
		{
			// для каждого элемента массива
			for (int i = 0; i < arrLen1; i++)
			{
				// сравнить элементы массива
				int result = arr1[arrOff1 + i].CompareTo(arr2[arrOff2 + i]);

				// сравнить элементы массива
				if (result != 0) return result;
			}
			// сравнить размеры массивов 
			return (arrLen1 == arrLen2) ? 0 : (arrLen1 < arrLen2 ? -1 : 1);
		}
		public static int Compare<T>(T[] arr1, T[] arr2) where T : IComparable<T>
		{
			// рассмотреть тривиальные случаи
			if (arr1 == null && arr2 == null) return  0; 
			if (arr1 == null && arr2 != null) return -1; 
			if (arr1 != null && arr2 == null) return  1; 

			// сравнить массивы на равенство
			return Compare(arr1, 0, arr1.Length, arr2, 0, arr2.Length);
		}
		/////////////////////////////////////////////////////////////////////////////
		// Скопировать элементы массива
		/////////////////////////////////////////////////////////////////////////////
        public static T[] CopyOf<T>(T[] array, int offset, int length)
        {
            // выделить память для массива
            T[] result = new T[length]; 

            // скопировать данные
            Array.Copy(array, offset, result, 0, length); return result; 
        }
        public static T[] CopyOf<T>(T[] array, int length) 
        { 
            // скопировать данные
            return CopyOf(array, 0, length); 
        }
        /////////////////////////////////////////////////////////////////////////////
	    // Изменение порядка следования байтов
	    /////////////////////////////////////////////////////////////////////////////
        public static void Reverse<T>(T[] arr, int offset, int length)
        {
            // для всех пар изменяемых байтов
            for (int i = 0; i < length / 2; i++)
            {
                // временно сохранить значение
                T temp = arr[offset + i]; 
            
                // изменить порядок следования байтов
                arr[offset + i] = arr[length + offset - i - 1];
            
                // изменить порядок следования байтов
                arr[length + offset - i - 1] = temp;
            }
        }
        public static void Reverse<T>(T[] arr) { Reverse(arr, 0, arr.Length); }

		/////////////////////////////////////////////////////////////////////////////
		// Преобразование типа объекта
		/////////////////////////////////////////////////////////////////////////////
		public static T[] Convert<T, U>(U[] array) where U : T
		{
			// выделить память для результата
			T[] result = new T[array.Length]; if (array.Length == 0) return result; 
 
			// скопировать массив
			Array.Copy(array, result, array.Length); return result; 
		}
		/////////////////////////////////////////////////////////////////////////////
		// Конкатенация массивов
		/////////////////////////////////////////////////////////////////////////////
		public static T[] Concat<T>(params T[][] arrays)
		{
			int length = 0; int cb = 0; 

			// определить общий размер массива
			for (int i = 0; i < arrays.Length; i++) length += arrays[i].Length;
 
			// выделить память для массива
			T[] array = new T[length]; 

			// для всех массивов
			for (int i = 0; i < arrays.Length; cb += arrays[i++].Length)
			{
				// скопировать массив
				Array.Copy(arrays[i], 0, array, cb, arrays[i].Length); 
			}
			return array; 
		}
	    /////////////////////////////////////////////////////////////////////////////
	    // Шестнадцатеричное представление массива
	    /////////////////////////////////////////////////////////////////////////////
	    public static byte[] FromHexString(string value)
	    {
	        // проверить размер строки
	        if ((value.Length % 2) != 0) throw new InvalidDataException(); 

	        // проверить наличие только цифр
	        for (int i = 0; i < value.Length; i++)
	        {
		        // проверить наличие только цифр
		        if (Char.IsDigit(value[i])) continue; 

		        // проверить наличие шестнадцатеричных символов
		        if ('A' <= value[i] && value[i] <= 'F') continue;
		        if ('a' <= value[i] && value[i] <= 'f') continue;

                // при ошибке выбросить исключение
		        throw new InvalidDataException();
	        }
            // указать способ кодирования
            NumberStyles style = NumberStyles.AllowHexSpecifier; 

	        // выделить буфер требуемого размера
	        byte[] buffer = new byte[value.Length / 2];  

	        // для каждого байта
	        for (int i = 0; i < value.Length / 2; i++)
	        {	
                // раскодировать байт
                buffer[i] = Byte.Parse(value.Substring(2 * i, 2), style); 
	        }
	        return buffer; 
	    }
	    public static string ToHexString(byte[] array)
        {
            // получить строковое представление
            return BitConverter.ToString(array).Replace("-", ""); 
        }
    }
}
