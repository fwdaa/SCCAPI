using System; 
using System.Collections.Generic; 
using System.IO;
using System.Reflection; 

namespace Aladdin.IO.Java
{
    ///////////////////////////////////////////////////////////////////////////
    // Создание сериализаций данных
    ///////////////////////////////////////////////////////////////////////////
    public class Serialization : IO.Serialization
    {
        // соответствие имени Java-класса и типа
        private Dictionary<String, ConstructorInfo> factory; 

        // конструктор
        public Serialization()
        {
            // инициализировать переменные
            factory = new Dictionary<String, ConstructorInfo>(); 
        }
        // добавить соответствие имени Java-класса и типа
        public void AddTypeMapping(string className, Type type)
        {
            // указать тип параметров конструктора
            Type[] constructorArgs = new Type[] { typeof(JavaObject) }; 

            // получить описание конструктора
            ConstructorInfo constructor = type.GetConstructor(constructorArgs); 

            // проверить наличие конструктора
            if (constructor == null) throw new InvalidOperationException(); 

            // добавить соответствие имени Java-класса и типа
            factory.Add(className, constructor); 
        }
        // создать способ записи/чтения данных
        public override IO.Serializer GetSerializer(Type type) 
        { 
            // создать способ записи/чтения данных
            return new Serializer(this); 
        } 
        // закодировать объект
        public byte[] Encode(object obj)
        {
            // проверить наличие объекта
            if (obj == null) return new byte[] { 0x70 }; 

            // создать список кодируемых объектов
            SerialStream stream = new SerialStream(); 

            // выполнить преобразование типа
            object javaObject = ToJavaObject(obj); 

            // закодировать объект
            byte[] encoded = stream.Encode(javaObject); 

            // выделить буфер требуемого размера
            byte[] buffer = new byte[4 + encoded.Length]; 

            // указать заголовок
            buffer[0] = 0xAC; buffer[1] = 0xED; // STREAM_MAGIC
            buffer[2] = 0x00; buffer[3] = 0x05; // STREAM_VERSION

            // скопировать закодированное представление
            Array.Copy(encoded, 0, buffer, 4, encoded.Length); 
            
            // выполнить тестовое раскодирование /* TODO */
            obj = Decode(buffer); return buffer; 
        }
        // раскодировать объект
        public object Decode(byte[] encoded)
        {
            // проверить корректность размера
            if (encoded.Length < 5) throw new InvalidDataException(); int size = 0; 

            // проверить совпадение заголовка
            if (encoded[0] != 0xAC || encoded[1] != 0xED) throw new InvalidDataException();
            if (encoded[2] != 0x00 || encoded[3] != 0x05) throw new InvalidDataException();

            // проверить наличие значения
            if (encoded[4] == 0x70) return null; object obj = null; 

            // создать список раскодированных объектов
            SerialStream stream = new SerialStream(); 

            // в зависимости от типа
            if (encoded[4] == 0x74 || encoded[4] == 0x7C)
            {
                // раскодировать объект
                obj = stream.DecodeString(encoded, 4, encoded.Length - 4, out size); 
            }
            // в зависимости от типа
            else if (encoded[4] == 0x73)
            {
                // раскодировать объект
                obj = stream.DecodeJavaObject(encoded, 4, encoded.Length - 4, out size); 
            }
            // в зависимости от типа
            else if (encoded[4] == 0x75)
            {
                // раскодировать массив
                obj = stream.DecodeJavaArray(encoded, 4, encoded.Length - 4, out size); 
            }
            // при ошибке выбросить исключение
            else throw new InvalidDataException(); 

            // проверить отсутствие лишних данных
            if (size != encoded.Length - 4) throw new InvalidDataException(); 

            // выполнить преобразование типа 
            return FromJavaObject(obj); 
        }
        // преобразовать тип объекта
        protected virtual object ToJavaObject(object obj) 
        { 
            // при наличии кодируемого объекта
            if (obj is ISerializable)
            { 
                // закодировать объект
                return ((ISerializable)obj).ToJavaObject(); 
            }
            return obj; 
        } 
        // преобразовать тип объекта
        protected virtual object FromJavaObject(object obj) 
        { 
            // при указании объекта Java
            if (obj is JavaObject) { JavaObject javaObject = (JavaObject)obj; 

                // определить имя класса Java
                string className = javaObject.Type.Name; 

                // при наличии имени типа в таблице
                if (factory.ContainsKey(className))
                {
                    // раскодировать объект 
                    try { return factory[className].Invoke(new object[] { javaObject }); }

                    // обработать возможное исключение
                    catch (TargetInvocationException e) { throw e.InnerException;  }
                }
            }
            return obj; 
        } 
    }
}
