using System; 
using System.IO; 
using System.Text; 
using System.Collections.Generic; 

namespace Aladdin.IO.Java
{
    ///////////////////////////////////////////////////////////////////////////
    // Список сериализованных объектов 
    ///////////////////////////////////////////////////////////////////////////
    public class SerialStream
    {
        // список сериализованных объектов 
        private List<Object> objects; 

        // список описаний классов
        private Dictionary<String, ClassDesc> classDescs; 

        // конструктор
        public SerialStream() { objects = new List<Object>(); 

            // создать список индексов описаний классов
            classDescs = new Dictionary<String, ClassDesc>(); 
        }
        // список сериализованных объектов 
        internal List<Object> Objects { get { return objects; }}

        // найти объект в списке
        private int IndexOf(object obj) 
        {
            // проверить наличие объекта
            if (obj == null) return -1; 

            // для всех объектов
            for (int i = 0; i < objects.Count; i++)
            {
                // проверить совпадение ссылки
                if (Object.ReferenceEquals(objects[i], obj)) return i; 
            }
            return -1; 
        }
        ///////////////////////////////////////////////////////////////////////////
        // Кодирование объектов
        ///////////////////////////////////////////////////////////////////////////
        public byte[] Encode(object obj)
        {
            // вернуть примитивные типы
            if (obj is  Boolean) return BooleanType .Instance.Encode(this, obj); 
            if (obj is    SByte) return ByteType    .Instance.Encode(this, obj); 
            if (obj is     Byte) return ByteType    .Instance.Encode(this, obj); 
            if (obj is    Int16) return ShortType   .Instance.Encode(this, obj); 
            if (obj is   UInt16) return ShortType   .Instance.Encode(this, obj); 
            if (obj is    Int32) return IntegerType .Instance.Encode(this, obj); 
            if (obj is   UInt32) return IntegerType .Instance.Encode(this, obj); 
            if (obj is    Int64) return LongType    .Instance.Encode(this, obj); 
            if (obj is   UInt64) return LongType    .Instance.Encode(this, obj); 
            if (obj is   Single) return FloatType   .Instance.Encode(this, obj); 
            if (obj is   Double) return DoubleType  .Instance.Encode(this, obj); 
            if (obj is     Char) return CharType    .Instance.Encode(this, obj); 
            if (obj is DateTime) return DateType    .Instance.Encode(this, obj); 

            // закодировать составные типы
            if (obj is String    ) return EncodeString    ((String    )obj); 
            if (obj is JavaArray ) return EncodeJavaArray ((JavaArray )obj); 
            if (obj is JavaObject) return EncodeJavaObject((JavaObject)obj); 

            // при ошибке выбросить исключение
            throw new NotSupportedException(); 
        }
        public byte[] Encode(string name, object obj)
        {
            // проверить корректность данных
            if (name.Length == 0) throw new InvalidDataException(); 

            // вернуть примитивные типы
            if (name == "boolean"       ) return BooleanType .Instance.Encode(this, obj); 
            if (name == "byte"          ) return ByteType    .Instance.Encode(this, obj); 
            if (name == "short"         ) return ShortType   .Instance.Encode(this, obj); 
            if (name == "int"           ) return IntegerType .Instance.Encode(this, obj); 
            if (name == "long"          ) return LongType    .Instance.Encode(this, obj); 
            if (name == "float"         ) return FloatType   .Instance.Encode(this, obj); 
            if (name == "double"        ) return DoubleType  .Instance.Encode(this, obj); 
            if (name == "char"          ) return CharType    .Instance.Encode(this, obj); 
            if (name == "java.util.Date") return DateType    .Instance.Encode(this, obj); 

            // закодировать строковый тип
            if (name == "java.lang.String") return EncodeString((String)obj); 

            // закодировать массив
            else if (name[0] == '[') return EncodeJavaArray((JavaArray)obj); 

            // закодировать объект
            else return EncodeJavaObject((JavaObject)obj);
        }
        // раскодировать объект
        public object Decode(string name, byte[] encoded, int offset, int length, out int size)
        {
            // проверить корректность данных
            if (name.Length == 0) throw new InvalidDataException(); 

            // раскодировать примитивный объект
            if (name == "boolean") return BooleanType.Instance.Decode(this, encoded, offset, length, out size); 
            if (name == "byte"   ) return ByteType   .Instance.Decode(this, encoded, offset, length, out size); 
            if (name == "short"  ) return ShortType  .Instance.Decode(this, encoded, offset, length, out size); 
            if (name == "int"    ) return IntegerType.Instance.Decode(this, encoded, offset, length, out size); 
            if (name == "long"   ) return LongType   .Instance.Decode(this, encoded, offset, length, out size); 
            if (name == "float"  ) return FloatType  .Instance.Decode(this, encoded, offset, length, out size); 
            if (name == "double" ) return DoubleType .Instance.Decode(this, encoded, offset, length, out size); 
            if (name == "char"   ) return CharType   .Instance.Decode(this, encoded, offset, length, out size); 

            // для строкового типа
            if (name == "java.lang.String") 
            {
                // раскодировать строковый тип
                return DecodeString(encoded, offset, length, out size); 
            }
            // для типа массивов
            else if (name[0] == '[')
            {
                // раскодировать массив
                return DecodeJavaArray(encoded, offset, length, out size); 
            }
            else { 
                // раскодировать объект
                return DecodeJavaObject(encoded, offset, length, out size); 
            }
        }
        ///////////////////////////////////////////////////////////////////////
        // Кодирование чисел
        ///////////////////////////////////////////////////////////////////////
        public byte[] EncodeShort(short value)
        {
            // закодировать значение
            byte[] encoded = new byte[2]; EncodeShort(value, encoded, 0); return encoded; 
        }
        public void EncodeShort(short value, byte[] encoded, int offset)
        {
            // закодировать значение
            encoded[offset + 0] = (byte)(((ushort)value >> 8) & 0xFF); 
            encoded[offset + 1] = (byte)(((ushort)value >> 0) & 0xFF); 
        }
        public short DecodeShort(byte[] encoded, int offset, int length)
        {
            // проверить корректность размера
            if (length < 2) throw new InvalidDataException(); 

            // раскодировать значение
            return (short)((encoded[offset] << 8) | encoded[offset + 1]); 
        }
        public short DecodeShort(byte[] encoded, int offset, int length, out int size)
        {
            // раскодировать значение
            size = 2; return DecodeShort(encoded, offset, length); 
        }
        // закодировать значение
        public byte[] EncodeInteger(int value)
        {
            // закодировать значение
            byte[] encoded = new byte[4]; EncodeInteger(value, encoded, 0); return encoded; 
        }
        // закодировать значение
        public void EncodeInteger(int value, byte[] encoded, int offset)
        {
            // закодировать значение
            encoded[offset + 0] = (byte)(((uint)value >> 24) & 0xFF); 
            encoded[offset + 1] = (byte)(((uint)value >> 16) & 0xFF); 
            encoded[offset + 2] = (byte)(((uint)value >>  8) & 0xFF); 
            encoded[offset + 3] = (byte)(((uint)value >>  0) & 0xFF); 
        }
        // раскодировать значение
        public int DecodeInteger(byte[] encoded, int offset, int length)
        {
            // проверить корректность размера
            if (length < 4) throw new InvalidDataException(); int value = 0; 

            // раскодировать значение
            value |= encoded[offset + 0] << 24; value |= encoded[offset + 1] << 16; 
            value |= encoded[offset + 2] <<  8; value |= encoded[offset + 3] <<  0; 

            return value; 
        }
        // раскодировать значение
        public int DecodeInteger(byte[] encoded, int offset, int length, out int size)
        {
            // раскодировать значение
            size = 4; return DecodeInteger(encoded, offset, length); 
        }
        // закодировать значение
        public byte[] EncodeLong(long value)
        {
            // закодировать значение
            byte[] encoded = new byte[8]; EncodeLong(value, encoded, 0); return encoded; 
        }
        // закодировать значение
        public void EncodeLong(long value, byte[] encoded, int offset)
        {
            // закодировать значение
            encoded[offset + 0] = (byte)(((ulong)value >> 56) & 0xFF); 
            encoded[offset + 1] = (byte)(((ulong)value >> 48) & 0xFF); 
            encoded[offset + 2] = (byte)(((ulong)value >> 40) & 0xFF); 
            encoded[offset + 3] = (byte)(((ulong)value >> 32) & 0xFF); 
            encoded[offset + 4] = (byte)(((ulong)value >> 24) & 0xFF); 
            encoded[offset + 5] = (byte)(((ulong)value >> 16) & 0xFF); 
            encoded[offset + 6] = (byte)(((ulong)value >>  8) & 0xFF); 
            encoded[offset + 7] = (byte)(((ulong)value >>  0) & 0xFF); 
        }
        // раскодировать значение
        public long DecodeLong(byte[] encoded, int offset, int length)
        {
            // проверить корректность размера
            if (length < 8) throw new InvalidDataException(); long value = 0;

            // раскодировать значение
            value |= (long)encoded[offset + 0] << 56; value |= (long)encoded[offset + 1] << 48;
            value |= (long)encoded[offset + 2] << 40; value |= (long)encoded[offset + 3] << 32;
            value |= (long)encoded[offset + 4] << 24; value |= (long)encoded[offset + 5] << 16;
            value |= (long)encoded[offset + 6] <<  8; value |= (long)encoded[offset + 7] <<  0;

            return value; 
        }
        // раскодировать значение
        public long DecodeLong(byte[] encoded, int offset, int length, out int size)
        {
            // раскодировать значение
            size = 8; return DecodeLong(encoded, offset, length); 
        }
        ///////////////////////////////////////////////////////////////////////
        // Кодирование имен
        ///////////////////////////////////////////////////////////////////////
        public byte[] EncodeName(string value)
        {
            // закодировать строку
            byte[] utf8 = Encoding.UTF8.GetBytes(value); int length = utf8.Length; 

            // проверить размер строки
            if (length > UInt16.MaxValue) throw new ArgumentException(); 

            // выделить буфер требуемого размера
            byte[] encoded = new byte[2 + length]; 

            // закодировать размер
            EncodeShort((short)length, encoded, 0); 

            // скопировать закодированную строку
            Array.Copy(utf8, 0, encoded, 2, length); return encoded;
        }
        // раскодировать имя
        public string DecodeName(byte[] encoded, int offset, int length, out int size)
        {
            // проверить корректность размера
            if (length < 2) throw new InvalidDataException(); 

            // раскодировать размер имени
            size = 2 + DecodeShort(encoded, offset, 2); 

            // проверить корректность размера
            if (length < size) throw new InvalidDataException();

            // раскодировать строку
            return Encoding.UTF8.GetString(encoded, offset + 2, size - 2); 
        }
        ///////////////////////////////////////////////////////////////////////
        // Кодирование строк
        ///////////////////////////////////////////////////////////////////////
        public byte[] EncodeString(string obj)
        {
            // проверить наличие объекта
            if (obj == null) return new byte[] { 0x70 }; int index = IndexOf(obj);

            // закодировать ссылку
            if (index >= 0) return EncodeReference(index); 

            // закодировать строку и добавить ее в список
            return StringType.Instance.Encode(this, obj); 
        }
        public string DecodeString(byte[] encoded, int offset, int length, out int size)
        {
            // проверить корректность размера 
            if (length < 1) throw new InvalidDataException(); size = 1; 
            
            // проверить наличие строки
            if (encoded[offset] == 0x70) return null; 
            
            // при указании ссылки
            else if (encoded[offset] == 0x71)
            { 
                // получить строку по ссылке
                return (string)DecodeReference(encoded, offset, length, out size); 
            }
            else { 
                // раскодировать строку и добавить ее в список
                return (string)StringType.Instance.Decode(this, encoded, offset, length, out size); 
            }
        }
        ///////////////////////////////////////////////////////////////////////
        // Кодирование описаний объектов
        ///////////////////////////////////////////////////////////////////////
        public byte[] EncodeClassDesc(ClassDesc obj)
        {
            // проверить наличие объекта
            if (obj == null) return new byte[] { 0x70 }; 

            // при наличии описания класса
            if (classDescs.ContainsKey(obj.Name)) { obj = classDescs[obj.Name];
            
                // закодировать ссылку
                return EncodeReference(IndexOf(obj));
            }
            else { 
                // добавить объект в список и закодировать значение
                classDescs.Add(obj.Name, obj); return obj.Encode(this);
            }
        }
        public ClassDesc DecodeClassDesc(byte[] encoded, int offset, int length, out int size)
        {
            // проверить корректность размера 
            if (length < 1) throw new InvalidDataException(); size = 1; 
            
            // проверить наличие описания
            if (encoded[offset] == 0x70) return null; 
            
            // при указании ссылки
            else if (encoded[offset] == 0x71)
            { 
                // получить описание объекта по ссылке
                return (ClassDesc)DecodeReference(encoded, offset, length, out size); 
            }
            else { 
                // раскодировать описание объекта
                ClassDesc obj = ClassDesc.Decode(this, encoded, offset, length, out size); 

                // добавить описание объекта в список
                classDescs.Add(obj.Name, obj); return obj; 
            }
        }
        ///////////////////////////////////////////////////////////////////////
        // Кодирование объектов
        ///////////////////////////////////////////////////////////////////////

        // закодировать объект
        public byte[] EncodeJavaObject(JavaObject obj)
        {
            // проверить наличие объекта
            if (obj == null) return new byte[] { 0x70 }; int index = IndexOf(obj);

            // закодировать ссылку
            if (index >= 0) return EncodeReference(index); 

            // закодировать значение и добавить его в список
            else return obj.Type.Encode(this, obj);  
        }
        // раскодировать объект
        public object DecodeJavaObject(byte[] encoded, int offset, int length, out int size)
        {
            // проверить корректность размера 
            if (length < 1) throw new InvalidDataException(); size = 1; 
            
            // проверить наличие объекта
            if (encoded[offset] == 0x70) return null; 

            // при указании ссылки
            else if (encoded[offset] == 0x71)
            { 
                // получить объект по ссылке
                return DecodeReference(encoded, offset, length, out size); 
            }
            else { 
                // раскодировать объект и добавить его в список
                return ObjectType.Decode(this, encoded, offset, length, out size); 
            }
        }
        ///////////////////////////////////////////////////////////////////////
        // Кодирование массивов
        ///////////////////////////////////////////////////////////////////////

        // закодировать массив
        public byte[] EncodeJavaArray(JavaArray obj)
        {
            // проверить наличие массива
            if (obj == null || obj.Value == null) return new byte[] { 0x70 }; 

            // закодировать ссылку
            int index = IndexOf(obj); if (index >= 0) return EncodeReference(index); 
            
            // закодировать значение и добавить его в список
            else return obj.Type.Encode(this, obj);  
        }
        // раскодировать массив
        public JavaArray DecodeJavaArray(byte[] encoded, int offset, int length, out int size)
        {
            // проверить корректность размера 
            if (length < 1) throw new InvalidDataException(); size = 1; 
            
            // проверить наличие массива
            if (encoded[offset] == 0x70) return null; 

            // при указании ссылки
            else if (encoded[offset] == 0x71)
            { 
                // получить массив по ссылке
                return (JavaArray)DecodeReference(encoded, offset, length, out size); 
            }
            else { 
                // раскодировать массив и добавить его в список
                return ArrayType.Decode(this, encoded, offset, length, out size); 
            }
        }
        ///////////////////////////////////////////////////////////////////////
        // Кодирование ссылок
        ///////////////////////////////////////////////////////////////////////

        // закодировать ссылку
        private byte[] EncodeReference(int index)
        {
            // выделить буфер требуемого размера
            byte[] encoded = new byte[5]; encoded[0] = 0x71; 

            // вычислить значение описателя
            int reference = 0x007E0000 + index; 

            // закодировать значение описателя
            EncodeInteger(reference, encoded, 1); return encoded; 
        }
        // раскодировать ссылку
        private object DecodeReference(byte[] encoded, int offset, int length, out int size)
        {
            // проверить корректность размера 
            if (length < 1) throw new InvalidDataException(); size = 1; 

            // проверить корректность данных
            if (encoded[offset] != 0x71) throw new InvalidDataException();

            // перейти на следующее поле
            int next = size; offset += next; length -= next; 

            // прочитать значение ссылки
            int reference = DecodeInteger(encoded, offset, length, out next); 

            // вернуть значение объекта
            size += next; return objects[reference - 0x007E0000]; 
        }
    }
}
