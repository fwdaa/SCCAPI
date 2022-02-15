package aladdin.math;
import aladdin.util.*; 
import java.math.*;
import java.util.*;

public final class Convert 
{
    ///////////////////////////////////////////////////////////////////////////
    // Кодирование 16-разрядных чисел
    ///////////////////////////////////////////////////////////////////////////
    public static short toInt16(byte[] buffer, int offset, Endian endian)
    {
        if (endian == Endian.BIG_ENDIAN)
        {
            // раскодировать число
            return (short)(((buffer[offset] & 0xFF) << 8) | (buffer[offset + 1] & 0xFF)); 
        }
        else {
            // раскодировать число
            return (short)(((buffer[offset + 1] & 0xFF) << 8) | (buffer[offset] & 0xFF)); 
        }
    }
    public static void fromInt16(short value, Endian endian, byte[] buffer, int offset)
    {
        if (endian == Endian.BIG_ENDIAN)
        {
            // закодировать число
            buffer[offset    ] = (byte)(value >>> 8); 
            buffer[offset + 1] = (byte)(value      ); 
        }
        else {
            // закодировать число
            buffer[offset    ] = (byte)(value      ); 
            buffer[offset + 1] = (byte)(value >>> 8); 
        }
    }
    public static byte[] fromInt16(short value, Endian endian)
    {
        // выделить буфер требуемого размера
        byte[] buffer = new byte[2]; 

        // закодировать число
        fromInt16(value, endian, buffer, 0); return buffer; 
    }
    ///////////////////////////////////////////////////////////////////////////
    // Кодирование 32-разрядных чисел
    ///////////////////////////////////////////////////////////////////////////
    public static int toInt32(byte[] buffer, int offset, Endian endian)
    {
        if (endian == Endian.BIG_ENDIAN)
        {
            // раскодировать число
            return ((buffer[offset    ] & 0xFF) << 24) | 
                   ((buffer[offset + 1] & 0xFF) << 16) | 
                   ((buffer[offset + 2] & 0xFF) <<  8) | 
                   ((buffer[offset + 3] & 0xFF)      ); 
        }
        else if (endian == Endian.LITTLE_ENDIAN) 
        {
            // раскодировать число
            return ((buffer[offset    ] & 0xFF)      ) | 
                   ((buffer[offset + 1] & 0xFF) <<  8) | 
                   ((buffer[offset + 2] & 0xFF) << 16) | 
                   ((buffer[offset + 3] & 0xFF) << 24); 
        }
        else {
            // D4*0x01 + C3*0x100 + B2*0x10000 + A1*0x1000000 -> B2, A1, D4, C3
            return ((buffer[offset + 1] & 0xFF) << 24) | 
                   ((buffer[offset + 0] & 0xFF) << 16) | 
                   ((buffer[offset + 3] & 0xFF) <<  8) |
                   ((buffer[offset + 2] & 0xFF)      );
        }
    }
    public static void fromInt32(int value, Endian endian, byte[] buffer, int offset)
    {
        if (endian == Endian.BIG_ENDIAN)
        {
            // закодировать число
            buffer[offset    ] = (byte)(value >>> 24); 
            buffer[offset + 1] = (byte)(value >>> 16); 
            buffer[offset + 2] = (byte)(value >>>  8); 
            buffer[offset + 3] = (byte)(value       ); 
        }
        else if (endian == Endian.LITTLE_ENDIAN) 
        {
            // закодировать число
            buffer[offset    ] = (byte)(value       ); 
            buffer[offset + 1] = (byte)(value >>>  8); 
            buffer[offset + 2] = (byte)(value >>> 16); 
            buffer[offset + 3] = (byte)(value >>> 24); 
        }
        else {
            // D4*0x01 + C3*0x100 + B2*0x10000 + A1*0x1000000 -> B2, A1, D4, C3
            buffer[offset + 0] = (byte)(value >>> 16);  
            buffer[offset + 1] = (byte)(value >>> 24);  
            buffer[offset + 2] = (byte)(value      );  
            buffer[offset + 3] = (byte)(value >>>  8); 
        }
    }
    public static byte[] fromInt32(int value, Endian endian)
    {
        // выделить буфер требуемого размера
        byte[] buffer = new byte[4]; 

        // закодировать число
        fromInt32(value, endian, buffer, 0); return buffer; 
    }
    ///////////////////////////////////////////////////////////////////////////
    // Кодирование 64-разрядных чисел
    ///////////////////////////////////////////////////////////////////////////
    public static long toInt64(byte[] buffer, int offset, Endian endian)
    {
        if (endian == Endian.BIG_ENDIAN)
        {
            // раскодировать число
            return ((long)(buffer[offset    ] & 0xFF) << 56) | 
                   ((long)(buffer[offset + 1] & 0xFF) << 48) | 
                   ((long)(buffer[offset + 2] & 0xFF) << 40) | 
                   ((long)(buffer[offset + 3] & 0xFF) << 32) |
                   ((long)(buffer[offset + 4] & 0xFF) << 24) | 
                   ((long)(buffer[offset + 5] & 0xFF) << 16) |                     
                   ((long)(buffer[offset + 6] & 0xFF) <<  8) | 
                   ((long)(buffer[offset + 7] & 0xFF)      ) ;
        }
        else {
            // раскодировать число
            return ((long)(buffer[offset    ] & 0xFF)      ) | 
                   ((long)(buffer[offset + 1] & 0xFF) <<  8) | 
                   ((long)(buffer[offset + 2] & 0xFF) << 16) | 
                   ((long)(buffer[offset + 3] & 0xFF) << 24) |
                   ((long)(buffer[offset + 4] & 0xFF) << 32) | 
                   ((long)(buffer[offset + 5] & 0xFF) << 40) |                     
                   ((long)(buffer[offset + 6] & 0xFF) << 48) | 
                   ((long)(buffer[offset + 7] & 0xFF) << 56) ;
        }
    }
    public static void fromInt64(long value, Endian endian, byte[] buffer, int offset)
    {
        if (endian == Endian.BIG_ENDIAN)
        {
            // закодировать число
            buffer[offset    ] = (byte)(value >>> 56); 
            buffer[offset + 1] = (byte)(value >>> 48); 
            buffer[offset + 2] = (byte)(value >>> 40); 
            buffer[offset + 3] = (byte)(value >>> 32); 
            buffer[offset + 4] = (byte)(value >>> 24); 
            buffer[offset + 5] = (byte)(value >>> 16); 
            buffer[offset + 6] = (byte)(value >>>  8); 
            buffer[offset + 7] = (byte)(value       ); 
        }
        else {
            // закодировать число
            buffer[offset    ] = (byte)(value       ); 
            buffer[offset + 1] = (byte)(value >>>  8); 
            buffer[offset + 2] = (byte)(value >>> 16); 
            buffer[offset + 3] = (byte)(value >>> 24); 
            buffer[offset + 4] = (byte)(value >>> 32); 
            buffer[offset + 5] = (byte)(value >>> 40); 
            buffer[offset + 6] = (byte)(value >>> 48); 
            buffer[offset + 7] = (byte)(value >>> 56); 
        }
    }
    public static byte[] fromInt64(long value, Endian endian)
    {
        // выделить буфер требуемого размера
        byte[] buffer = new byte[8]; 

        // закодировать число
        fromInt64(value, endian, buffer, 0); return buffer; 
    }
    ////////////////////////////////////////////////////////////////////////////
    // Кодирование вещественных чисел
    ////////////////////////////////////////////////////////////////////////////
    public static float toFloat(byte[] encoded, int offset, Endian endian)
    {
        // раскодировать целочисленный тип
        int intValue = toInt32(encoded, offset, endian); 
        
        // раскодировать вещественное число
        return Float.intBitsToFloat(intValue); 
    }
    public static void fromFloat(float value, Endian endian, byte[] encoded, int offset)
    {
        // получить целочисленное представление
        int intValue = Float.floatToRawIntBits(value); 

        // закодировать целочисленное представление
        fromInt32(intValue, endian, encoded, offset);
    }
    public static byte[] fromFloat(float value, Endian endian)
    {
        // выделить буфер требуемого размера
        byte[] result = new byte[4]; 
        
        // закодировать число
        fromFloat(value, endian, result, 0); return result; 
    }
    public static double toDouble(byte[] encoded, int offset, Endian endian)
    {
        // раскодировать целочисленный тип
        long longValue = toInt64(encoded, offset, endian); 
        
        // раскодировать вещественное число
        return Double.longBitsToDouble(longValue); 
    }
    public static void fromDouble(double value, Endian endian, byte[] encoded, int offset)
    {
        // получить целочисленное представление
        long longValue = Double.doubleToRawLongBits(value); 

        // закодировать целочисленное представление
        fromInt64(longValue, endian, encoded, offset);
    }
    public static byte[] fromDouble(double value, Endian endian)
    {
        // выделить буфер требуемого размера
        byte[] result = new byte[8]; 
        
        // закодировать число
        fromDouble(value, endian, result, 0); return result; 
    }
    ///////////////////////////////////////////////////////////////////////////
    // Кодирование неотрицательных чисел переменного размера
    ///////////////////////////////////////////////////////////////////////////
    public static BigInteger toBigInteger(byte[] buffer, int offset, int length, Endian endian)
    {
        // извлечь буфер требуемого размера
        buffer = Arrays.copyOfRange(buffer, offset, offset + length); 
        
        // изменить порядок следования байтов
        if (endian == Endian.LITTLE_ENDIAN) Array.reverse(buffer);
        
        // раскодировать число
        return new BigInteger(1, buffer); 
    }
    // раскодировать число
    public static BigInteger toBigInteger(byte[] buffer, Endian endian)
    {
        // в зависимости от способа кодирования
        if (endian == Endian.LITTLE_ENDIAN) 
        {  
            // изменить порядок следования байтов
            buffer = buffer.clone(); Array.reverse(buffer);
        }
        // раскодировать число
        return new BigInteger(1, buffer); 
    }
    // закодировать число
    public static byte[] fromBigInteger(BigInteger value, Endian endian)
    {
        // проверить корректность вызова
        if (value.signum() < 0) throw new IllegalArgumentException(); 

        // закодировать число
        byte[] buffer = value.toByteArray(); if (buffer[0] == 0) 
        {
            // нормализовать большое число
            buffer = Arrays.copyOfRange(buffer, 1, buffer.length);
        }
        // изменить порядок следования байтов
        if (endian == Endian.LITTLE_ENDIAN) Array.reverse(buffer); return buffer; 
    }    
    ///////////////////////////////////////////////////////////////////////////
    // Кодирование неотрицательных чисел переменного размера с дополнением нулями
    ///////////////////////////////////////////////////////////////////////////
    public static void fromBigInteger(BigInteger value, 
       Endian endian, byte[] buffer, int offset, int length)
    {
        // проверить корректность вызова
        if (value.signum() < 0) throw new IllegalArgumentException(); 

        // получить закодированное представление
        byte[] encoded = value.toByteArray(); if (encoded[0] == 0)
        {
            // проверить размер данных
            if (encoded.length - 1 > length) throw new IllegalArgumentException();
            
            // вычислить смещение числа в буфера
            int position = offset + length - (encoded.length - 1); 
            
            // обнулить неиспользуемые данные
            for (int i = offset; i < position; i++) buffer[i] = 0; 
            
            // скопировать закодированное представление
            System.arraycopy(encoded, 1, buffer, position, encoded.length - 1); 
        }
        else {
            // проверить размер данных
            if (encoded.length > length) throw new IllegalArgumentException();
            
            // вычислить смещение числа в буфера
            int position = offset + length - encoded.length; 
            
            // обнулить неиспользуемые данные
            for (int i = offset; i < position; i++) buffer[i] = 0; 
            
            // скопировать закодированное представление
            System.arraycopy(encoded, 0, buffer, position, encoded.length); 
        }
        // изменить порядок следования байтов
        if (endian == Endian.LITTLE_ENDIAN) Array.reverse(buffer, offset, length);  
    }
    public static byte[] fromBigInteger(BigInteger value, Endian endian, int length)
    {
        // выделить буфер требуемого размера
        byte[] buffer = new byte[length]; 
        
        // закодировать число
        fromBigInteger(value, endian, buffer, 0, length); return buffer; 
    }
}
