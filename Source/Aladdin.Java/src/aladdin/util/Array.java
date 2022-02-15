package aladdin.util;
import java.io.*; 
    
public final class Array
{
    /////////////////////////////////////////////////////////////////////////////
    // Сравнение массивов на равенство
    /////////////////////////////////////////////////////////////////////////////
    public static boolean equals(
        boolean[] arr1, int arrOff1, boolean[] arr2, int arrOff2, int arrLen)
    {
        // для всех элементов массива
        for (int i = 0; i < arrLen; i++)
        {
            // сравнить элементы массива
            if (arr1[arrOff1 + i] != arr2[arrOff2 + i]) return false; 
        }
        return true; 
    }
    public static boolean equals(
        char[] arr1, int arrOff1, char[] arr2, int arrOff2, int arrLen)
    {
        // для всех элементов массива
        for (int i = 0; i < arrLen; i++)
        {
            // сравнить элементы массива
            if (arr1[arrOff1 + i] != arr2[arrOff2 + i]) return false; 
        }
        return true; 
    }
    public static boolean equals(
        byte[] arr1, int arrOff1, byte[] arr2, int arrOff2, int arrLen)
    {
        // для всех элементов массива
        for (int i = 0; i < arrLen; i++)
        {
            // сравнить элементы массива
            if (arr1[arrOff1 + i] != arr2[arrOff2 + i]) return false; 
        }
        return true; 
    }
    public static boolean equals(
        short[] arr1, int arrOff1, short[] arr2, int arrOff2, int arrLen)
    {
        // для всех элементов массива
        for (int i = 0; i < arrLen; i++)
        {
            // сравнить элементы массива
            if (arr1[arrOff1 + i] != arr2[arrOff2 + i]) return false; 
        }
        return true; 
    }
    public static boolean equals(
        int[] arr1, int arrOff1, int[] arr2, int arrOff2, int arrLen)
    {
        // для всех элементов массива
        for (int i = 0; i < arrLen; i++)
        {
            // сравнить элементы массива
            if (arr1[arrOff1 + i] != arr2[arrOff2 + i]) return false; 
        }
        return true; 
    }
    public static boolean equals(
        long[] arr1, int arrOff1, long[] arr2, int arrOff2, int arrLen)
    {
        // для всех элементов массива
        for (int i = 0; i < arrLen; i++)
        {
            // сравнить элементы массива
            if (arr1[arrOff1 + i] != arr2[arrOff2 + i]) return false; 
        }
        return true; 
    }
    public static boolean equals(
        float[] arr1, int arrOff1, float[] arr2, int arrOff2, int arrLen)
    {
        // для всех элементов массива
        for (int i = 0; i < arrLen; i++)
        {
            // сравнить элементы массива
            if (arr1[arrOff1 + i] != arr2[arrOff2 + i]) return false; 
        }
        return true; 
    }
    public static boolean equals(
        double[] arr1, int arrOff1, double[] arr2, int arrOff2, int arrLen)
    {
        // для всех элементов массива
        for (int i = 0; i < arrLen; i++)
        {
            // сравнить элементы массива
            if (arr1[arrOff1 + i] != arr2[arrOff2 + i]) return false; 
        }
        return true; 
    }
    public static <T> boolean equals(
        T[] arr1, int arrOff1, T[] arr2, int arrOff2, int arrLen)
    {
        // для всех элементов массива
        for (int i = 0; i < arrLen; i++)
        {
            // сравнить элементы массива
            if (!arr1[arrOff1 + i].equals(arr2[arrOff2 + i])) return false; 
        }
        return true; 
    }
    /////////////////////////////////////////////////////////////////////////////
    // Знаковое сравнение массивов на неравенство
    /////////////////////////////////////////////////////////////////////////////
    public static int compareSigned(
        byte[] arr1, int arrOff1, int arrLen1, 
        byte[] arr2, int arrOff2, int arrLen2)
    {
        // для каждого элемента массива
		for (int i = 0; i < arrLen1; i++)
		{
            // извлечь знаковое значение
            int val1 = arr1[arrOff1 + i];
            int val2 = arr2[arrOff2 + i];
            
            // сравнить элементы массива
            if (val1 != val2) return (val1 < val2) ? -1 : 1;
		}
		// сравнить размеры массивов 
		return (arrLen1 == arrLen2) ? 0 : (arrLen1 < arrLen2 ? -1 : 1);
    }
    public static int compareSigned(
        short[] arr1, int arrOff1, int arrLen1, 
        short[] arr2, int arrOff2, int arrLen2)
    {
        // для каждого элемента массива
		for (int i = 0; i < arrLen1; i++)
		{
            // извлечь знаковое значение
            int val1 = arr1[arrOff1 + i];
            int val2 = arr2[arrOff2 + i];
            
            // сравнить элементы массива
            if (val1 != val2) return (val1 < val2) ? -1 : 1;
		}
		// сравнить размеры массивов 
		return (arrLen1 == arrLen2) ? 0 : (arrLen1 < arrLen2 ? -1 : 1);
    }
    public static int compareSigned(
        int[] arr1, int arrOff1, int arrLen1, 
        int[] arr2, int arrOff2, int arrLen2)
    {
        // для каждого элемента массива
		for (int i = 0; i < arrLen1; i++)
		{
            // извлечь знаковое значение
            int val1 = arr1[arrOff1 + i];
            int val2 = arr2[arrOff2 + i];
            
            // сравнить элементы массива
            if (val1 != val2) return (val1 < val2) ? -1 : 1;
		}
		// сравнить размеры массивов 
		return (arrLen1 == arrLen2) ? 0 : (arrLen1 < arrLen2 ? -1 : 1);
    }
    public static int compareSigned(
        long[] arr1, int arrOff1, int arrLen1, 
        long[] arr2, int arrOff2, int arrLen2)
    {
        // для каждого элемента массива
		for (int i = 0; i < arrLen1; i++)
		{
            // извлечь знаковое значение
            long val1 = arr1[arrOff1 + i];
            long val2 = arr2[arrOff2 + i];
            
            // сравнить элементы массива
            if (val1 != val2) return (val1 < val2) ? -1 : 1;
		}
		// сравнить размеры массивов 
		return (arrLen1 == arrLen2) ? 0 : (arrLen1 < arrLen2 ? -1 : 1);
    }
    /////////////////////////////////////////////////////////////////////////////
    // Беззнаковое сравнение массивов на неравенство
    /////////////////////////////////////////////////////////////////////////////
    public static int compareUnsigned(
        byte[] arr1, int arrOff1, int arrLen1, 
        byte[] arr2, int arrOff2, int arrLen2)
    {
        // для каждого элемента массива
		for (int i = 0; i < arrLen1; i++)
		{
            // извлечь беззнаковое значение
            int val1 = arr1[arrOff1 + i] & 0x000000FF;
            int val2 = arr2[arrOff2 + i] & 0x000000FF;
            
            // сравнить элементы массива
            if (val1 != val2) return (val1 < val2) ? -1 : 1;
		}
		// сравнить размеры массивов 
		return (arrLen1 == arrLen2) ? 0 : (arrLen1 < arrLen2 ? -1 : 1);
    }
    public static int compareUnsigned(
        short[] arr1, int arrOff1, int arrLen1, 
        short[] arr2, int arrOff2, int arrLen2)
    {
        // для каждого элемента массива
		for (int i = 0; i < arrLen1; i++)
		{
            // извлечь беззнаковое значение
            int val1 = arr1[arrOff1 + i] & 0x0000FFFF;
            int val2 = arr2[arrOff2 + i] & 0x0000FFFF;
            
            // сравнить элементы массива
            if (val1 != val2) return (val1 < val2) ? -1 : 1;
		}
		// сравнить размеры массивов 
		return (arrLen1 == arrLen2) ? 0 : (arrLen1 < arrLen2 ? -1 : 1);
    }
    public static int compareUnsigned(
        int[] arr1, int arrOff1, int arrLen1, 
        int[] arr2, int arrOff2, int arrLen2)
    {
        // для каждого элемента массива
		for (int i = 0; i < arrLen1; i++)
		{
            // извлечь беззнаковое значение
            long val1 = arr1[arrOff1 + i] & 0xFFFFFFFFL;
            long val2 = arr2[arrOff2 + i] & 0xFFFFFFFFL;
            
            // сравнить элементы массива
            if (val1 != val2) return (val1 < val2) ? -1 : 1;
		}
		// сравнить размеры массивов 
		return (arrLen1 == arrLen2) ? 0 : (arrLen1 < arrLen2 ? -1 : 1);
    }
    public static int compareUnsigned(
        long[] arr1, int arrOff1, int arrLen1, 
        long[] arr2, int arrOff2, int arrLen2)
    {
        // для каждого элемента массива
		for (int i = 0; i < arrLen1; i++)
		{
            // извлечь беззнаковое значение
            long val1 = arr1[arrOff1 + i]; long val2 = arr2[arrOff2 + i];
            
            // проверить значения на равенство
            if (val1 == val2) continue; 
            
            // сравнить элементы
            return ((val1 < val2) ^ (val1 < 0) ^ (val2 < 0)) ? -1 : 1;
		}
		// сравнить размеры массивов 
		return (arrLen1 == arrLen2) ? 0 : (arrLen1 < arrLen2 ? -1 : 1);
    }
    /////////////////////////////////////////////////////////////////////////////
    // Сравнение массивов на неравенство
    /////////////////////////////////////////////////////////////////////////////
    public static int compareSigned(byte[] arr1, byte[] arr2)
    {
        // проверить указание массивов
        if (arr1 == null) arr1 = new byte[0]; if (arr2 == null) arr2 = new byte[0];
        
		// сравнить массивы на равенство
		return compareSigned(arr1, 0, arr1.length, arr2, 0, arr2.length);
    }
    public static int compareUnsigned(byte[] arr1, byte[] arr2)
    {
        // проверить указание массивов
        if (arr1 == null) arr1 = new byte[0]; if (arr2 == null) arr2 = new byte[0];
        
		// сравнить массивы на равенство
		return compareUnsigned(arr1, 0, arr1.length, arr2, 0, arr2.length);
    }
    public static int compareSigned(short[] arr1, short[] arr2)
    {
        // проверить указание массивов
        if (arr1 == null) arr1 = new short[0]; if (arr2 == null) arr2 = new short[0];
        
		// сравнить массивы на равенство
		return compareSigned(arr1, 0, arr1.length, arr2, 0, arr2.length);
    }
    public static int compareUnsigned(short[] arr1, short[] arr2)
    {
        // проверить указание массивов
        if (arr1 == null) arr1 = new short[0]; if (arr2 == null) arr2 = new short[0];
        
		// сравнить массивы на равенство
		return compareUnsigned(arr1, 0, arr1.length, arr2, 0, arr2.length);
    }
    public static int compareSigned(int[] arr1, int[] arr2)
    {
        // проверить указание массивов
        if (arr1 == null) arr1 = new int[0]; if (arr2 == null) arr2 = new int[0];
        
		// сравнить массивы на равенство
		return compareSigned(arr1, 0, arr1.length, arr2, 0, arr2.length);
    }
    public static int compareUnsigned(int[] arr1, int[] arr2)
    {
        // проверить указание массивов
        if (arr1 == null) arr1 = new int[0]; if (arr2 == null) arr2 = new int[0];
        
		// сравнить массивы на равенство
		return compareUnsigned(arr1, 0, arr1.length, arr2, 0, arr2.length);
    }
    public static int compareSigned(long[] arr1, long[] arr2)
    {
        // проверить указание массивов
        if (arr1 == null) arr1 = new long[0]; if (arr2 == null) arr2 = new long[0];
        
		// сравнить массивы на равенство
		return compareSigned(arr1, 0, arr1.length, arr2, 0, arr2.length);
    }
    public static int compareUnsigned(long[] arr1, long[] arr2)
    {
        // проверить указание массивов
        if (arr1 == null) arr1 = new long[0]; if (arr2 == null) arr2 = new long[0];
        
		// сравнить массивы на равенство
		return compareUnsigned(arr1, 0, arr1.length, arr2, 0, arr2.length);
    }
    /////////////////////////////////////////////////////////////////////////////
	// Изменение порядка следования байтов
	/////////////////////////////////////////////////////////////////////////////
    public static void reverse(boolean[] arr, int offset, int length)
    {
        // для всех пар изменяемых байтов
        for (int i = 0; i < length / 2; i++)
        {
            // изменить порядок следования байтов
            arr[offset + i] ^= arr[length + offset - i - 1];
            arr[length + offset - i - 1] ^= arr[offset + i];
            arr[offset + i] ^= arr[length + offset - i - 1];
        }
    }
    public static void reverse(byte[] arr, int offset, int length)
    {
        // для всех пар изменяемых байтов
        for (int i = 0; i < length / 2; i++)
        {
            // изменить порядок следования байтов
            arr[offset + i] ^= arr[length + offset - i - 1];
            arr[length + offset - i - 1] ^= arr[offset + i];
            arr[offset + i] ^= arr[length + offset - i - 1];
        }
    }
    public static void reverse(short[] arr, int offset, int length)
    {
        // для всех пар изменяемых байтов
        for (int i = 0; i < length / 2; i++)
        {
            // изменить порядок следования байтов
            arr[offset + i] ^= arr[length + offset - i - 1];
            arr[length + offset - i - 1] ^= arr[offset + i];
            arr[offset + i] ^= arr[length + offset - i - 1];
        }
    }
    public static void reverse(int[] arr, int offset, int length)
    {
        // для всех пар изменяемых байтов
        for (int i = 0; i < length / 2; i++)
        {
            // изменить порядок следования байтов
            arr[offset + i] ^= arr[length + offset - i - 1];
            arr[length + offset - i - 1] ^= arr[offset + i];
            arr[offset + i] ^= arr[length + offset - i - 1];
        }
    }
    public static void reverse(long[] arr, int offset, int length)
    {
        // для всех пар изменяемых байтов
        for (int i = 0; i < length / 2; i++)
        {
            // изменить порядок следования байтов
            arr[offset + i] ^= arr[length + offset - i - 1];
            arr[length + offset - i - 1] ^= arr[offset + i];
            arr[offset + i] ^= arr[length + offset - i - 1];
        }
    }
    public static void reverse(float[] arr, int offset, int length)
    {
        // для всех пар изменяемых байтов
        for (int i = 0; i < length / 2; i++)
        {
            // временно сохранить значение
            float temp = arr[offset + i]; 
            
            // изменить порядок следования байтов
            arr[offset + i] = arr[length + offset - i - 1];
            
            // изменить порядок следования байтов
            arr[length + offset - i - 1] = temp;
        }
    }
    public static void reverse(double[] arr, int offset, int length)
    {
        // для всех пар изменяемых байтов
        for (int i = 0; i < length / 2; i++)
        {
            // временно сохранить значение
            double temp = arr[offset + i]; 
            
            // изменить порядок следования байтов
            arr[offset + i] = arr[length + offset - i - 1];
            
            // изменить порядок следования байтов
            arr[length + offset - i - 1] = temp;
        }
    }
    public static <T> void reverse(T[] arr, int offset, int length)
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
    public static     void reverse(boolean[] arr) { reverse(arr, 0, arr.length); }
    public static     void reverse(byte   [] arr) { reverse(arr, 0, arr.length); }
    public static     void reverse(short  [] arr) { reverse(arr, 0, arr.length); }
    public static     void reverse(int    [] arr) { reverse(arr, 0, arr.length); }
    public static     void reverse(long   [] arr) { reverse(arr, 0, arr.length); }
    public static     void reverse(float  [] arr) { reverse(arr, 0, arr.length); }
    public static     void reverse(double [] arr) { reverse(arr, 0, arr.length); }
    public static <T> void reverse(T      [] arr) { reverse(arr, 0, arr.length); }
    
    /////////////////////////////////////////////////////////////////////////////
	// Конкатенация массивов
	/////////////////////////////////////////////////////////////////////////////
	public static boolean[] concat(boolean[]... arrays)
	{
		int length = 0; int offset = 0; 

		// определить общий размер массива
		for (int i = 0; i < arrays.length; i++) length += arrays[i].length;
 
		// выделить память для массива
		boolean[] array = new boolean[length]; 

		// для всех массивов
		for (int i = 0; i < arrays.length; offset += arrays[i++].length)
		{
			// скопировать массив
			System.arraycopy(arrays[i], 0, array, offset, arrays[i].length); 
		}
		return array; 
	}
	public static byte[] concat(byte[]... arrays)
	{
		int length = 0; int offset = 0; 

		// определить общий размер массива
		for (int i = 0; i < arrays.length; i++) length += arrays[i].length;
 
		// выделить память для массива
		byte[] array = new byte[length]; 

		// для всех массивов
		for (int i = 0; i < arrays.length; offset += arrays[i++].length)
		{
			// скопировать массив
			System.arraycopy(arrays[i], 0, array, offset, arrays[i].length); 
		}
		return array; 
	}
	public static short[] concat(short[]... arrays)
	{
		int length = 0; int offset = 0; 

		// определить общий размер массива
		for (int i = 0; i < arrays.length; i++) length += arrays[i].length;
 
		// выделить память для массива
		short[] array = new short[length]; 

		// для всех массивов
		for (int i = 0; i < arrays.length; offset += arrays[i++].length)
		{
			// скопировать массив
			System.arraycopy(arrays[i], 0, array, offset, arrays[i].length); 
		}
		return array; 
	}
	public static int[] concat(int[]... arrays)
	{
		int length = 0; int offset = 0; 

		// определить общий размер массива
		for (int i = 0; i < arrays.length; i++) length += arrays[i].length;
 
		// выделить память для массива
		int[] array = new int[length]; 

		// для всех массивов
		for (int i = 0; i < arrays.length; offset += arrays[i++].length)
		{
			// скопировать массив
			System.arraycopy(arrays[i], 0, array, offset, arrays[i].length); 
		}
		return array; 
	}
	public static long[] concat(long[]... arrays)
	{
		int length = 0; int offset = 0; 

		// определить общий размер массива
		for (int i = 0; i < arrays.length; i++) length += arrays[i].length;
 
		// выделить память для массива
		long[] array = new long[length]; 

		// для всех массивов
		for (int i = 0; i < arrays.length; offset += arrays[i++].length)
		{
			// скопировать массив
			System.arraycopy(arrays[i], 0, array, offset, arrays[i].length); 
		}
		return array; 
	}
	public static float[] concat(float[]... arrays)
	{
		int length = 0; int offset = 0; 

		// определить общий размер массива
		for (int i = 0; i < arrays.length; i++) length += arrays[i].length;
 
		// выделить память для массива
		float[] array = new float[length]; 

		// для всех массивов
		for (int i = 0; i < arrays.length; offset += arrays[i++].length)
		{
			// скопировать массив
			System.arraycopy(arrays[i], 0, array, offset, arrays[i].length); 
		}
		return array; 
	}
	public static double[] concat(double[]... arrays)
	{
		int length = 0; int offset = 0; 

		// определить общий размер массива
		for (int i = 0; i < arrays.length; i++) length += arrays[i].length;
 
		// выделить память для массива
		double[] array = new double[length]; 

		// для всех массивов
		for (int i = 0; i < arrays.length; offset += arrays[i++].length)
		{
			// скопировать массив
			System.arraycopy(arrays[i], 0, array, offset, arrays[i].length); 
		}
		return array; 
	}
	public static Object[] concat(Object[]... arrays)
	{
		int length = 0; int cb = 0; 

		// определить общий размер массива
		for (int i = 0; i < arrays.length; i++) length += arrays[i].length;
 
		// выделить память для массива
		Object[] array = new Object[length]; 

		// для всех массивов
		for (int i = 0; i < arrays.length; cb += arrays[i++].length)
		{
			// скопировать массив
			System.arraycopy(arrays[i], 0, array, cb, arrays[i].length); 
		}
		return array; 
	}
    @SuppressWarnings({"unchecked"}) 
	public static <T> T[] concat(Class<? extends T> componentType, T[]... arrays)
	{
		int length = 0; int cb = 0; 

		// определить общий размер массива
		for (int i = 0; i < arrays.length; i++) length += arrays[i].length;
 
		// выделить память для массива
		T[] array = (T[])java.lang.reflect.Array.newInstance(componentType, length); 

		// для всех массивов
		for (int i = 0; i < arrays.length; cb += arrays[i++].length)
		{
			// скопировать массив
			System.arraycopy(arrays[i], 0, array, cb, arrays[i].length); 
		}
		return array; 
	}
	/////////////////////////////////////////////////////////////////////////////
	// Шестнадцатеричное представление массива
	/////////////////////////////////////////////////////////////////////////////
    public static byte[] fromHexString(String value) throws IOException
    {
	    // проверить размер строки
	    if ((value.length() % 2) != 0) throw new IOException(); 

	    // проверить наличие только цифр
	    for (int i = 0; i < value.length(); i++)
	    {
            // извлечь символ строки
            char ch = value.charAt(i); 
            
		    // проверить наличие только цифр
		    if (Character.isDigit(ch)) continue; 

		    // проверить наличие шестнадцатеричных символов
		    if ('A' <= ch && ch <= 'F') continue;
		    if ('a' <= ch && ch <= 'f') continue;

            // выбросить исключение
		    throw new IOException();
	    }
        // выделить буфер требуемого размера
	    byte[] buffer = new byte[value.length() / 2];  

	    // для каждого байта
	    for (int i = 0; i < value.length() / 2; i++)
	    {	
            // извлечь подстроку
            String substr = value.substring(2 * i, 2 * i + 2); 
            
            // раскодировать байт
            buffer[i] = (byte)(Short.parseShort(substr, 16) & 0xFF); 
	    }
	    return buffer; 
    }
    // вернуть шестнадцатеричное представление
	public static String toHexString(byte[] arr, int off, int len)
    {
        // создать строковый буфер
        StringBuilder buffer = new StringBuilder(); 

        // для всех байтов 
        for (int i = 0; i < len; i++)
        {
            // получить шестнадцатеричное представление
            buffer.append(String.format("%1$02X", arr[off + i] & 0xFF)); 
        }
        // вернуть представление
        return buffer.toString(); 
    }
    // вернуть шестнадцатеричное представление
    public static String toHexString(byte[] arr) 
    { 
        // вернуть шестнадцатеричное представление
        return toHexString(arr, 0, arr.length); 
    }
}
