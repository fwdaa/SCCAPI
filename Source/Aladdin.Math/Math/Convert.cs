using System;

namespace Aladdin.Math
{
    public static class Convert
    {
        ///////////////////////////////////////////////////////////////////////////
        // Кодирование 16-разрядных чисел
        ///////////////////////////////////////////////////////////////////////////
        public static short ToInt16(byte[] buffer, int offset, Endian endian)
        {
            if (endian == Endian.BigEndian)
            {
                // раскодировать число
                return (short)((buffer[offset + 0] << 8) | buffer[offset + 1]); 
            }
            else {
                // раскодировать число
                return (short)((buffer[offset + 1] << 8) | buffer[offset + 0]); 
            }
        }
        public static ushort ToUInt16(byte[] buffer, int offset, Endian endian)
        {
            if (endian == Endian.BigEndian)
            {
                // раскодировать число
                return (ushort)((buffer[offset + 0] << 8) | buffer[offset + 1]); 
            }
            else {
                // раскодировать число
                return (ushort)((buffer[offset + 1] << 8) | buffer[offset + 0]); 
            }
        }
        public static void FromUInt16(ushort value, Endian endian, byte[] buffer, int offset)
        {
            if (endian == Endian.BigEndian)
            {
                // закодировать число
                buffer[offset + 0] = (byte)(value >> 8); 
                buffer[offset + 1] = (byte)(value >> 0); 
            }
            else {
                // закодировать число
                buffer[offset + 0] = (byte)(value >> 0); 
                buffer[offset + 1] = (byte)(value >> 8); 
            }
        }
        public static void FromInt16(short value, Endian endian, byte[] buffer, int offset)
        {
            if (endian == Endian.BigEndian)
            {
                // закодировать число
                buffer[offset + 0] = (byte)(value >> 8); 
                buffer[offset + 1] = (byte)(value >> 0); 
            }
            else {
                // закодировать число
                buffer[offset + 0] = (byte)(value >> 0); 
                buffer[offset + 1] = (byte)(value >> 8); 
            }
        }
        public static byte[] FromUInt16(ushort value, Endian endian)
        {
            // выделить буфер требуемого размера
            byte[] buffer = new byte[2]; 

            // закодировать число
            FromUInt16(value, endian, buffer, 0); return buffer; 
        }
        public static byte[] FromInt16(short value, Endian endian)
        {
            // выделить буфер требуемого размера
            byte[] buffer = new byte[2]; 

            // закодировать число
            FromInt16(value, endian, buffer, 0); return buffer; 
        }
        ///////////////////////////////////////////////////////////////////////////
        // Кодирование 32-разрядных чисел
        ///////////////////////////////////////////////////////////////////////////
        public static uint ToUInt32(byte[] buffer, int offset, Endian endian)
        {
            if (endian == Endian.BigEndian)
            {
                // раскодировать число
                return (uint)(buffer[offset + 0] << 24) | 
                       (uint)(buffer[offset + 1] << 16) | 
                       (uint)(buffer[offset + 2] <<  8) | 
                       (uint)(buffer[offset + 3] <<  0); 
            }
            else if (endian == Endian.LittleEndian)
            {
                // раскодировать число
                return (uint)(buffer[offset + 0] <<  0) | 
                       (uint)(buffer[offset + 1] <<  8) | 
                       (uint)(buffer[offset + 2] << 16) | 
                       (uint)(buffer[offset + 3] << 24); 
            }
            else {
                // D4*0x01 + C3*0x100 + B2*0x10000 + A1*0x1000000 -> B2, A1, D4, C3
                return (uint)(buffer[offset + 1] << 24) | 
                       (uint)(buffer[offset + 0] << 16) | 
                       (uint)(buffer[offset + 3] <<  8) |
                       (uint)(buffer[offset + 2] <<  0);
            }
        }
        public static int ToInt32(byte[] buffer, int offset, Endian endian)
        {
            if (endian == Endian.BigEndian)
            {
                // раскодировать число
                return (int)(buffer[offset + 0] << 24) | 
                       (int)(buffer[offset + 1] << 16) | 
                       (int)(buffer[offset + 2] <<  8) | 
                       (int)(buffer[offset + 3] <<  0); 
            }
            else if (endian == Endian.LittleEndian)
            {
                // раскодировать число
                return (int)(buffer[offset + 0] <<  0) | 
                       (int)(buffer[offset + 1] <<  8) | 
                       (int)(buffer[offset + 2] << 16) | 
                       (int)(buffer[offset + 3] << 24); 
            }
            else {
                // D4*0x01 + C3*0x100 + B2*0x10000 + A1*0x1000000 -> B2, A1, D4, C3
                return (int)(buffer[offset + 1] << 24) | 
                       (int)(buffer[offset + 0] << 16) | 
                       (int)(buffer[offset + 3] <<  8) |
                       (int)(buffer[offset + 2] <<  0);
            }
        }
        public static void FromUInt32(uint value, Endian endian, byte[] buffer, int offset)
        {
            if (endian == Endian.BigEndian)
            {
                // закодировать число
                buffer[offset + 0] = (byte)(value >> 24); 
                buffer[offset + 1] = (byte)(value >> 16); 
                buffer[offset + 2] = (byte)(value >>  8); 
                buffer[offset + 3] = (byte)(value >>  0); 
            }
            else if (endian == Endian.LittleEndian)
            {
                // закодировать число
                buffer[offset + 0] = (byte)(value >>  0); 
                buffer[offset + 1] = (byte)(value >>  8); 
                buffer[offset + 2] = (byte)(value >> 16); 
                buffer[offset + 3] = (byte)(value >> 24); 
            }
            else {
                // D4*0x01 + C3*0x100 + B2*0x10000 + A1*0x1000000 -> B2, A1, D4, C3
                buffer[offset + 0] = (byte)(value >> 16);  
                buffer[offset + 1] = (byte)(value >> 24);  
                buffer[offset + 2] = (byte)(value >>  0);  
                buffer[offset + 3] = (byte)(value >>  8); 
            }
        }
        public static void FromInt32(int value, Endian endian, byte[] buffer, int offset)
        {
            if (endian == Endian.BigEndian)
            {
                // закодировать число
                buffer[offset + 0] = (byte)(value >> 24); 
                buffer[offset + 1] = (byte)(value >> 16); 
                buffer[offset + 2] = (byte)(value >>  8); 
                buffer[offset + 3] = (byte)(value >>  0); 
            }
            else if (endian == Endian.LittleEndian)
            {
                // закодировать число
                buffer[offset + 0] = (byte)(value >>  0); 
                buffer[offset + 1] = (byte)(value >>  8); 
                buffer[offset + 2] = (byte)(value >> 16); 
                buffer[offset + 3] = (byte)(value >> 24); 
            }
            else {
                // D4*0x01 + C3*0x100 + B2*0x10000 + A1*0x1000000 -> B2, A1, D4, C3
                buffer[offset + 0] = (byte)(value >> 16);  
                buffer[offset + 1] = (byte)(value >> 24);  
                buffer[offset + 2] = (byte)(value >>  0);  
                buffer[offset + 3] = (byte)(value >>  8); 
            }
        }
        public static byte[] FromUInt32(uint value, Endian endian)
        {
            // выделить буфер требуемого размера
            byte[] buffer = new byte[4]; 

            // закодировать число
            FromUInt32(value, endian, buffer, 0); return buffer; 
        }
        public static byte[] FromInt32(int value, Endian endian)
        {
            // выделить буфер требуемого размера
            byte[] buffer = new byte[4]; 

            // закодировать число
            FromInt32(value, endian, buffer, 0); return buffer; 
        }
        ///////////////////////////////////////////////////////////////////////////
        // Кодирование 64-разрядных чисел
        ///////////////////////////////////////////////////////////////////////////
        public static ulong ToUInt64(byte[] buffer, int offset, Endian endian)
        {
            if (endian == Endian.BigEndian)
            {
                // раскодировать число
                return ((ulong)buffer[offset + 0] << 56) | 
                       ((ulong)buffer[offset + 1] << 48) | 
                       ((ulong)buffer[offset + 2] << 40) | 
                       ((ulong)buffer[offset + 3] << 32) |
                       ((ulong)buffer[offset + 4] << 24) | 
                       ((ulong)buffer[offset + 5] << 16) |                     
                       ((ulong)buffer[offset + 6] <<  8) | 
                       ((ulong)buffer[offset + 7] <<  0) ;
            }
            else {
                // раскодировать число
                return ((ulong)buffer[offset + 0] <<  0) | 
                       ((ulong)buffer[offset + 1] <<  8) | 
                       ((ulong)buffer[offset + 2] << 16) | 
                       ((ulong)buffer[offset + 3] << 24) |
                       ((ulong)buffer[offset + 4] << 32) | 
                       ((ulong)buffer[offset + 5] << 40) |                     
                       ((ulong)buffer[offset + 6] << 48) | 
                       ((ulong)buffer[offset + 7] << 56) ;
            }
        }
        public static long ToInt64(byte[] buffer, int offset, Endian endian)
        {
            if (endian == Endian.BigEndian)
            {
                // раскодировать число
                return ((long)buffer[offset + 0] << 56) | 
                       ((long)buffer[offset + 1] << 48) | 
                       ((long)buffer[offset + 2] << 40) | 
                       ((long)buffer[offset + 3] << 32) |
                       ((long)buffer[offset + 4] << 24) | 
                       ((long)buffer[offset + 5] << 16) |                     
                       ((long)buffer[offset + 6] <<  8) | 
                       ((long)buffer[offset + 7] <<  0) ;
            }
            else {
                // раскодировать число
                return ((long)buffer[offset + 0] <<  0) | 
                       ((long)buffer[offset + 1] <<  8) | 
                       ((long)buffer[offset + 2] << 16) | 
                       ((long)buffer[offset + 3] << 24) |
                       ((long)buffer[offset + 4] << 32) | 
                       ((long)buffer[offset + 5] << 40) |                     
                       ((long)buffer[offset + 6] << 48) | 
                       ((long)buffer[offset + 7] << 56) ;
            }
        }
        public static void FromUInt64(ulong value, Endian endian, byte[] buffer, int offset)
        {
            if (endian == Endian.BigEndian)
            {
                // закодировать число
                buffer[offset + 0] = (byte)(value >> 56); 
                buffer[offset + 1] = (byte)(value >> 48); 
                buffer[offset + 2] = (byte)(value >> 40); 
                buffer[offset + 3] = (byte)(value >> 32); 
                buffer[offset + 4] = (byte)(value >> 24); 
                buffer[offset + 5] = (byte)(value >> 16); 
                buffer[offset + 6] = (byte)(value >>  8); 
                buffer[offset + 7] = (byte)(value >>  0); 
            }
            else {
                // закодировать число
                buffer[offset + 0] = (byte)(value >>  0); 
                buffer[offset + 1] = (byte)(value >>  8); 
                buffer[offset + 2] = (byte)(value >> 16); 
                buffer[offset + 3] = (byte)(value >> 24); 
                buffer[offset + 4] = (byte)(value >> 32); 
                buffer[offset + 5] = (byte)(value >> 40); 
                buffer[offset + 6] = (byte)(value >> 48); 
                buffer[offset + 7] = (byte)(value >> 56); 
            }
        }
        public static void FromInt64(long value, Endian endian, byte[] buffer, int offset)
        {
            if (endian == Endian.BigEndian)
            {
                // закодировать число
                buffer[offset + 0] = (byte)(value >> 56); 
                buffer[offset + 1] = (byte)(value >> 48); 
                buffer[offset + 2] = (byte)(value >> 40); 
                buffer[offset + 3] = (byte)(value >> 32); 
                buffer[offset + 4] = (byte)(value >> 24); 
                buffer[offset + 5] = (byte)(value >> 16); 
                buffer[offset + 6] = (byte)(value >>  8); 
                buffer[offset + 7] = (byte)(value >>  0); 
            }
            else {
                // закодировать число
                buffer[offset + 0] = (byte)(value >>  0); 
                buffer[offset + 1] = (byte)(value >>  8); 
                buffer[offset + 2] = (byte)(value >> 16); 
                buffer[offset + 3] = (byte)(value >> 24); 
                buffer[offset + 4] = (byte)(value >> 32); 
                buffer[offset + 5] = (byte)(value >> 40); 
                buffer[offset + 6] = (byte)(value >> 48); 
                buffer[offset + 7] = (byte)(value >> 56); 
            }
        }
        public static byte[] FromUInt64(ulong value, Endian endian)
        {
            // выделить буфер требуемого размера
            byte[] buffer = new byte[8]; 

            // закодировать число
            FromUInt64(value, endian, buffer, 0); return buffer; 
        }
        public static byte[] FromInt64(long value, Endian endian)
        {
            // выделить буфер требуемого размера
            byte[] buffer = new byte[8]; 

            // закодировать число
            FromInt64(value, endian, buffer, 0); return buffer; 
        }
        ////////////////////////////////////////////////////////////////////////////
        // Кодирование вещественных чисел
        ////////////////////////////////////////////////////////////////////////////
        public static float ToFloat(byte[] encoded, int offset, Endian endian)
        {
            // раскодировать целочисленный тип
            encoded = FromInt32(ToInt32(encoded, offset, endian), Endian.LittleEndian); 
        
            // раскодировать вещественное число
            return BitConverter.ToSingle(encoded, 0); 
        }
        public static void FromFloat(float value, Endian endian, byte[] encoded, int offset)
        {
            // получить целочисленное представление
            int intValue = ToInt32(BitConverter.GetBytes(value), 0, Endian.LittleEndian); 

            // закодировать целочисленное представление
            FromInt32(intValue, endian, encoded, offset);
        }
        public static byte[] FromFloat(float value, Endian endian)
        {
            // выделить буфер требуемого размера
            byte[] result = new byte[4]; 
            
            // закодировать число
            FromFloat(value, endian, result, 0); return result; 
        }
        public static double ToDouble(byte[] encoded, int offset, Endian endian)
        {
            // раскодировать целочисленный тип
            long longValue = ToInt64(encoded, offset, endian); 
        
            // раскодировать вещественное число
            return BitConverter.Int64BitsToDouble(longValue); 
        }
        public static void FromDouble(double value, Endian endian, byte[] encoded, int offset)
        {
            // получить целочисленное представление
            long longValue = BitConverter.DoubleToInt64Bits(value); 

            // закодировать целочисленное представление
            FromInt64(longValue, endian, encoded, offset);
        }
        public static byte[] FromDouble(double value, Endian endian)
        {
            // выделить буфер требуемого размера
            byte[] result = new byte[8]; 
            
            // закодировать число
            FromDouble(value, endian, result, 0); return result; 
        }
#if !STANDALONE
        ///////////////////////////////////////////////////////////////////////////
        // Кодирование неотрицательных чисел переменного размера
        ///////////////////////////////////////////////////////////////////////////
        public static Math.BigInteger ToBigInteger(byte[] buffer, int offset, int length, Endian endian)
        {
            // извлечь буфер требуемого размера
            byte[] buf = new byte[length]; Array.Copy(buffer, offset, buf, 0, length); 
                
            // изменить порядок следования байтов
            if (endian == Endian.LittleEndian) Array.Reverse(buf);
        
            // раскодировать число
            return new Math.BigInteger(1, buf); 
        }
        // раскодировать число
        public static Math.BigInteger ToBigInteger(byte[] buffer, Endian endian)
        {
            // в зависимости от способа кодирования
            if (endian == Endian.LittleEndian) 
            {  
                // изменить порядок следования байтов
                buffer = (byte[])buffer.Clone(); Array.Reverse(buffer);
            }
            // раскодировать число
            return new Math.BigInteger(1, buffer); 
        }
        public static byte[] FromBigInteger(Math.BigInteger value, Endian endian)
        {
            // проверить корректность вызова
            if (value.Signum < 0) throw new ArgumentException(); 

            // закодировать число
            byte[] buffer = value.ToByteArray(); if (buffer[0] == 0) 
            {
                // выделить вспомогательный буфер
                byte[] buf = new byte[buffer.Length - 1]; 
                
                // нормализовать большое число
                Array.Copy(buffer, 1, buf, 0, buffer.Length - 1); buffer = buf; 
            }
            // изменить порядок следования байтов
            if (endian == Endian.LittleEndian) Array.Reverse(buffer); return buffer; 
        }    
        ///////////////////////////////////////////////////////////////////////////
        // Кодирование неотрицательных чисел переменного размера с дополнением нулями
        ///////////////////////////////////////////////////////////////////////////
        public static void FromBigInteger(Math.BigInteger value, 
            Endian endian, byte[] buffer, int offset, int length)
        {
            // проверить корректность вызова
            if (value.Signum < 0) throw new ArgumentException(); 

            // получить закодированное представление
            byte[] encoded = value.ToByteArray(); if (encoded[0] == 0)
            {
                // проверить размер данных
                if (encoded.Length - 1 > length) throw new ArgumentException();
            
                // вычислить смещение числа в буфера
                int position = offset + length - (encoded.Length - 1); 
            
                // обнулить неиспользуемые данные
                for (int i = offset; i < position; i++) buffer[i] = 0; 
            
                // скопировать закодированное представление
                Array.Copy(encoded, 1, buffer, position, encoded.Length - 1); 
            }
            else {
                // проверить размер данных
                if (encoded.Length > length) throw new ArgumentException();
            
                // вычислить смещение числа в буфера
                int position = offset + length - encoded.Length; 
            
                // обнулить неиспользуемые данные
                for (int i = offset; i < position; i++) buffer[i] = 0; 
            
                // скопировать закодированное представление
                Array.Copy(encoded, 0, buffer, position, encoded.Length); 
            }
            // изменить порядок следования байтов
            if (endian == Endian.LittleEndian) Array.Reverse(buffer, offset, length);  
        }
        public static byte[] FromBigInteger(Math.BigInteger value, Endian endian, int length)
        {
            // выделить буфер требуемого размера
            byte[] buffer = new byte[length]; 
        
            // закодировать число
            FromBigInteger(value, endian, buffer, 0, length); return buffer; 
        }
#endif 
    }
}
