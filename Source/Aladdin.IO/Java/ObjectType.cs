using System;
using System.IO;

namespace Aladdin.IO.Java
{
    ///////////////////////////////////////////////////////////////////////////
    // Описание класса Java
    ///////////////////////////////////////////////////////////////////////////
    public class ObjectType : JavaType
    {
        // создать описание класса Java
        public static ObjectType Create(ClassDesc classDesc)
        {
            // обработать частный случай
            if (classDesc.Name == "java.util.Date") return DateType.Instance; 

            // создать описание класса Java
            return new ObjectType(classDesc); 
        }
        // раскодировать значение
        public static object Decode(SerialStream stream,
            byte[] encoded, int offset, int length, out int size) 
        {
            // проверить корректность данных
            if (length < 1) throw new InvalidDataException(); size = 1; 

            // проверить наличие значения
            if (encoded[offset] == 0x70) return null; 

            // проверить корректность данных
            if (encoded[offset] != 0x73) throw new InvalidDataException(); 

            // пропустить заголовок
            int next = size; offset += next; length -= next; 

            // прочитать описание класса
            ClassDesc classDesc = stream.DecodeClassDesc(encoded, offset, length, out next); 

            // проверить корректность имени
            if (classDesc.Name.Length < 1 || classDesc.Name[0] == '[') 
            {
                // при ошибке выбросить исключение
                throw new InvalidDataException();
            }
            // перейти на следующее поле
            size += next; offset += next; length -= next;

            // зарезервировать слот в списке
            int index = stream.Objects.Count; stream.Objects.Add(null); 

            // указать тип объекта
            ObjectType classType = ObjectType.Create(classDesc); 

            // раскодировать значение
            object obj = classType.DecodeValue(stream, encoded, offset, length, out next); 

            // добавить объект в список
            size += next; stream.Objects[index] = obj; return obj; 
        }
        // описание класса
        public readonly ClassDesc ClassDesc; 

        // конструктор
        protected ObjectType(ClassDesc classDesc) 
        { 
            // проверить корректность данных
            if (classDesc.Name.Length < 1) throw new ArgumentException(); 

            // проверить корректность данных
            if (classDesc.Name[0] == '[') throw new ArgumentException(); 

            // сохранить переданные параметры
            ClassDesc = classDesc; 
        } 
        // имя типа 
        public override string Name { get { return ClassDesc.Name; }}

        // декорированное имя типа
        public override string DecoratedName { get 
        { 
            // сокращенное имя типа
            return String.Format("L{0};", Name.Replace('.', '/')); 
        }}
        // раскодировать значение
        public virtual object DecodeValue(
            SerialStream stream, byte[] encoded, int offset, int length, out int size)
        {
            // при наличии базового класса
            JavaObject parent = null; size = 0; if (ClassDesc.ParentDesc != null)
            {
                // указать тип базового класса
                ObjectType parentType = new ObjectType(ClassDesc.ParentDesc); 

                // раскодировать базовый класс
                parent = (JavaObject)parentType.DecodeValue(stream, encoded, offset, length, out size); 
            }
            // перейти на следующее поле
            int next = size; offset += next; length -= next; 

            // создать список значений полей
            Field[] fields = new Field[ClassDesc.Fields.Length]; 

            // для всех полей
            for (int i = 0; i < fields.Length; i++)
            {
                // определить тип поля
                string type = ClassDesc.Fields[i].Type; 

                // раскодировать объект
                object value = stream.Decode(type, encoded, offset, length, out next); 

                // добавить значение поля в список
                fields[i] = new Field(ClassDesc.Fields[i].Name, type, value); 

                // перейти на следующее поле
                size += next; offset += next; length -= next;
            }
            // вернуть значение класса
            return new JavaObject(this, parent, fields); 
        }
        // закодировать значение
        public virtual byte[] EncodeValue(SerialStream stream, object o)
        {
            // выполнить преобразование типа
            JavaObject obj = (JavaObject)o; 

            // проверить совпадение числа полей
            if (ClassDesc.Fields.Length != obj.FieldsCount) throw new ArgumentException(); 

            // при наличии базового класса
            byte[] encodedParent = new byte[0]; if (obj.Parent == null)
            {
                // проверить корректность данных
                if (ClassDesc.ParentDesc != null) throw new ArgumentException();  
            }
            else {
                // проверить корректность данных
                if (ClassDesc.ParentDesc == null) throw new ArgumentException(); 
 
                // проверить совпадение имени типа
                if (obj.Parent.Type.Name != ClassDesc.ParentDesc.Name)
                {
                    // при ошибке выбросить исключение
                    throw new ArgumentException(); 
                }
                // закодировать значения полей базового класса
                encodedParent = obj.Parent.Type.EncodeValue(stream, obj.Parent); 
            }
            // инициализировать общий размер
            int total = encodedParent.Length; 

            // создать список закодированных значений
            byte[][] encodedValues = new byte[ClassDesc.Fields.Length][]; 

            // для всех полей
            for (int i = 0; i < encodedValues.Length; i++)
            {
                // получить значение поля
                object fieldValue = obj.GetObject(ClassDesc.Fields[i].Name); 

                // закодировать значение поля
                encodedValues[i] = stream.Encode(ClassDesc.Fields[i].Type, fieldValue); 

                // увеличить общий размер
                total += encodedValues[i].Length; 
            }
            // выделить буфер требуемого размера
            byte[] encoded = new byte[total]; total = 0; 

            // скопировать значения базового класса
            Array.Copy(encodedParent, 0, encoded, total, encodedParent.Length); 
            
            // перейти на следующее поле
            total = total + encodedParent.Length; 

            // для всех полей
            for (int i = 0; i < encodedValues.Length; i++)
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

            // закодировать описание класса
            byte[] encodedClass = stream.EncodeClassDesc(ClassDesc); 
            
            // добавить объект в список
            stream.Objects.Add(value); 

            // закодировать значение класса
            byte[] encodedValue = EncodeValue(stream, value); 

            // инициализировать общий размер
            int total = 1 + encodedClass.Length + encodedValue.Length;
            
            // выделить буфер требуемого размера
            byte[] encoded = new byte[total]; encoded[0] = 0x73; total = 1; 

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
