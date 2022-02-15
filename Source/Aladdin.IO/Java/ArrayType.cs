using System;
using System.IO;

namespace Aladdin.IO.Java
{
    ///////////////////////////////////////////////////////////////////////////
    // Описание массива Java
    ///////////////////////////////////////////////////////////////////////////
    public class ArrayType : JavaType
    {
        // идентификаторы сериализации массивов примитивных типов
        public const long BooleanArrayUID =  6309297032502205922L; 
        public const long ByteArrayUID    = -5984413125824719648L; 
        public const long ShortArrayUID   = -1188055269542874886L; 
        public const long IntegerArrayUID =  5600894804908749477L; 
        public const long LongArrayUID    =  8655923659555304851L; 
        public const long FloatArrayUID   =   836686056779680834L; 
        public const long DoubleArrayUID  =  4514449696888150558L; 
        public const long CharArrayUID    = -5753798564021173076L; 
        public const long StringArrayUID  = -5921575005990323385L; 
        public const long DateArrayUID    =  4834372995424393440L;

        // создать массив определенного типа
        public static Array CreateInstance(string name, int length)
        {
            // проверить корректность данных
            if (name.Length < 2 || name[0] != '[') throw new InvalidDataException(); 
            
            switch (name[1])
            {
            // создать массив примитивных элементов
            case 'Z': return new Boolean[length];
            case 'B': return new    Byte[length];
            case 'S': return new   Int16[length];
            case 'I': return new   Int32[length];
            case 'J': return new   Int64[length];
            case 'F': return new  Single[length];
            case 'D': return new  Double[length];
            case 'C': return new    Char[length];
            }
            // создать массив строк
            if (name == "[Ljava.lang.String;") return new String[length]; 

            // создать массив дат
            else if (name == "[Ljava.util.Date;") return new DateTime[length]; 

            // создать массив массивов
            else if (name.StartsWith("[[")) return new JavaArray[length];

            // создать массив объектов
            else return new JavaObject[length]; 
        }
        // раскодировать значение
        public static JavaArray Decode(SerialStream stream,
            byte[] encoded, int offset, int length, out int size) 
        {
            // проверить корректность данных
            if (length < 1) throw new InvalidDataException(); size = 1; 

            // проверить наличие значения
            if (encoded[offset] == 0x70) return null; 

            // проверить корректность данных
            if (encoded[offset] != 0x75) throw new InvalidDataException(); 

            // пропустить заголовок
            int next = size; offset += next; length -= next; 

            // прочитать описание класса
            ClassDesc classDesc = stream.DecodeClassDesc(encoded, offset, length, out next); 

            // проверить корректность имени
            if (classDesc.Name.Length < 2 || classDesc.Name[0] != '[') 
            {
                // при ошибке выбросить исключение
                throw new InvalidDataException();
            }
            // перейти на следующее поле
            size += next; offset += next; length -= next;

            // зарезервировать слот в списке
            int index = stream.Objects.Count; stream.Objects.Add(null); 

            // указать тип массива
            ArrayType arrayType = new ArrayType(classDesc.Name, classDesc.SerialUID); 

            // раскодировать значение
            JavaArray array = arrayType.DecodeValue(stream, encoded, offset, length, out next); 

            // добавить объект в список
            size += next; stream.Objects[index] = array; return array; 
        }
        // тип массива, серийный номер и тип элементов
        private string name; private long serialUID; private string elementType;  

        // конструктор
        public ArrayType(string name, long serialUID) 
         { 
            // проверить корректность данных
            if (name.Length < 2) throw new ArgumentException(); 

            // проверить корректность данных
            if (name[0] != '[') throw new ArgumentException(); 

            // сохранить переданные параметры
            this.name = name; this.serialUID = serialUID; 

            // определить тип элементов массива
            elementType = JavaType.UndecorateType(name.Substring(1)); 
        } 
        // имя типа 
        public override string Name { get { return name; }}
        // декорированное имя типа
        public override string DecoratedName { get { return name; }}

        // раскодировать значение
        public JavaArray DecodeValue(SerialStream stream,
            byte[] encoded, int offset, int length, out int size)
        {
            // прочитать размер массива
            int count = stream.DecodeInteger(encoded, offset, length, out size); 

            // перейти на следующее поле
            int next = size; offset += next; length -= next;

            // выделить массив требуемого размера
            Array array = ArrayType.CreateInstance(name, count); 

            // определить тип элемента
            string elementType = JavaType.UndecorateType(name.Substring(1)); 

            // для всех объектов
            for (int i = 0; i < count; i++)
            {
                // раскодировать значение
                array.SetValue(stream.Decode(elementType, 
                    encoded, offset, length, out next), i
                ); 
                // перейти на следующее поле
                size += next; offset += next; length -= next;
            }
            // вернуть массив
            return new JavaArray(this, array); 
        }
        // закодировать значение
        public byte[] EncodeValue(SerialStream stream, JavaArray array)
        {
            // закодировать число элементов массива
            byte[] encodedSize = stream.EncodeInteger(array.Value.Length); 

            // инициализировать общий размер
            int total = encodedSize.Length;
            
            // создать список закодированных значений
            byte[][] encodedValues = new byte[array.Value.Length][]; 

            // для всех полей
            for (int i = 0; i < array.Value.Length; i++)
            {
                // получить значение поля
                object fieldValue = array.Value.GetValue(i); 

                // закодировать значение поля
                encodedValues[i] = stream.Encode(elementType, fieldValue); 

                // увеличить общий размер
                total += encodedValues[i].Length; 
            }
            // выделить буфер требуемого размера
            byte[] encoded = new byte[total]; total = 0; 

            // скопировать общий размер массива
            Array.Copy(encodedSize, 0, encoded, total, encodedSize.Length); 

            // перейти на следующее поле
            total = total + encodedSize.Length; 

            // для всех полей
            for (int i = 0; i < array.Value.Length; i++)
            {
                // скопировать закодированное значение
                Array.Copy(encodedValues[i], 0, encoded, total, encodedValues[i].Length); 

                // перейти на следующее поле
                total += encodedValues[i].Length; 
            }
            return encoded; 
        }
        // закодировать тип и значение
        public override byte[] Encode(SerialStream stream, object value)
        {
            // проверить наличие объекта
            if (value == null) return new byte[] { 0x70 }; 

            // создать описание класса
            ClassDesc classDesc = new ClassDesc(name, serialUID, ClassDesc.SC_SERIALIZABLE, null); 

            // закодировать описание класса
            byte[] encodedClass = stream.EncodeClassDesc(classDesc); 
            
            // добавить объект в список
            stream.Objects.Add(value); 

            // закодировать значение класса
            byte[] encodedValue = EncodeValue(stream, (JavaArray)value); 

            // инициализировать общий размер
            int total = 1 + encodedClass.Length + encodedValue.Length;
            
            // выделить буфер требуемого размера
            byte[] encoded = new byte[total]; encoded[0] = 0x75; total = 1; 

            // скопировать описание класса
            Array.Copy(encodedClass, 0, encoded, total, encodedClass.Length); 
            
            // перейти на следующее поле
            total = total + encodedClass.Length; 

            // скопировать значение класса
            Array.Copy(encodedValue, 0, encoded, total, encodedValue.Length); 

            // перейти на следующее поле
            total = total + encodedValue.Length; return encoded; 
        }
    }
}
