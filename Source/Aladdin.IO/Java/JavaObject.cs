using System;
using System.Collections.Generic;

namespace Aladdin.IO.Java
{
    ///////////////////////////////////////////////////////////////////////////
    // Описание объекта Java
    ///////////////////////////////////////////////////////////////////////////
    public class JavaObject
    {
        // базовый подобъект и тип объекта 
        public readonly JavaObject Parent; public readonly ObjectType Type; 

        // поля объекта
        private Field[] fields; private Dictionary<String, Int32> indexes;

        // конструктор
        public JavaObject(string type, long serialUID, byte flags, JavaObject parent, params Field[] fields)
        {
            // создать описание полей
            FieldDesc[] fieldDescriptions = new FieldDesc[fields.Length]; 

            // переупорядочить поля
            this.fields = Field.RearrangeFields(fields); 

            // для всех полей
            for (int i = 0; i < fieldDescriptions.Length; i++)
            {
                // сохранить описание поля
                fieldDescriptions[i] = this.fields[i].Description; 
            }
            // указать описание родительского класса
            ClassDesc parentDesc = (parent != null) ? parent.Type.ClassDesc : null; 

            // создать описание класса
            ClassDesc classDescription = new ClassDesc(
                type, serialUID, flags, parentDesc, fieldDescriptions
            ); 
            // сохранить переданные параметры
            Parent = parent; Type = ObjectType.Create(classDescription); 

            // создать список полей объекта
            indexes = new Dictionary<String, Int32>(); 

            // для всех полей объектов
            for (int i = 0; i < this.fields.Length; i++)
            {
                // сохранить поле объекта
                indexes.Add(this.fields[i].Name, i); 
            }
        }
        // конструктор
        public JavaObject(string type, long serialUID, JavaObject parent, params Field[] fields)

            // указать возможностиь сериализации
            : this(type, serialUID, ClassDesc.SC_SERIALIZABLE, parent, fields) {}

        // конструктор
        public JavaObject(ObjectType type, JavaObject parent, params Field[] fields)
        {
            // сохранить переданные параметры
            Parent = parent; Type = type; 
            
            // переупорядочить поля
            this.fields = Field.RearrangeFields(fields); 

            // создать список полей объекта
            indexes = new Dictionary<String, Int32>(); 

            // для всех полей объектов
            for (int i = 0; i < this.fields.Length; i++)
            {
                // сохранить поле объекта
                indexes.Add(this.fields[i].Name, i); 
            }
        }
        // конструктор
        public JavaObject(ClassDesc type, JavaObject parent, params Field[] fields)

            // сохранить переданные параметры
            : this(ObjectType.Create(type), parent, fields) {} 

        // получить число полей
        public int FieldsCount { get { return fields.Length; }}

        // получить значение поля
        public object GetObject(string name) { return fields[indexes[name]].Value; }

        // получить значение поля
        public bool   GetBoolean(string name) { return Convert.ToBoolean(GetObject(name)); }
        public char   GetChar   (string name) { return Convert.ToChar   (GetObject(name)); }
        public byte   GetByte   (string name) { return Convert.ToByte   (GetObject(name)); }
        public short  GetShort  (string name) { return Convert.ToInt16  (GetObject(name)); }
        public int    GetInteger(string name) { return Convert.ToInt32  (GetObject(name)); }
        public long   GetLong   (string name) { return Convert.ToInt64  (GetObject(name)); }
        public float  GetFloat  (string name) { return Convert.ToSingle (GetObject(name)); }
        public double GetDouble (string name) { return Convert.ToDouble (GetObject(name)); }

        // получить значение поля
        public string GetString (string name) { object obj = GetObject(name); 

            // вернуть значение поля
            return (obj != null) ? Convert.ToString(obj) : null; 
        }
        // получить значение объекта или массива
        public JavaObject GetJavaObject(string name) { return (JavaObject)GetObject(name); }
        public JavaArray  GetJavaArray (string name) { return (JavaArray )GetObject(name); }

        public bool[] GetBooleanArray(string name) 
        { 
            // получить значение массива
            JavaArray array = GetJavaArray(name); 

            // вернуть значение массива
            return (bool[])(array != null ? array.Value : null); 
        }
        public char[] GetCharArray(string name) 
        { 
            // получить значение массива
            JavaArray array = GetJavaArray(name); 
            
            // вернуть значение массива
            return (char[])(array != null ? array.Value : null); 
        }
        public byte[] GetByteArray(string name) 
        { 
            // получить значение массива
            JavaArray array = GetJavaArray(name); 

            // вернуть значение массива
            return (byte[])(array != null ? array.Value : null); 
        }
        public short[] GetShortArray(string name) 
        { 
            // получить значение массива
            JavaArray array = GetJavaArray(name); 

            // вернуть значение массива
            return (short[])(array != null ? array.Value : null); 
        }
        public int[] GetIntegerArray(string name) 
        { 
            // получить значение массива
            JavaArray array = GetJavaArray(name); 

            // вернуть значение массива
            return (int[])(array != null ? array.Value : null); 
        }
        public long[] GetLongArray(string name) 
        { 
            // получить значение массива
            JavaArray array = GetJavaArray(name); 

            // вернуть значение массива
            return (long[])(array != null ? array.Value : null); 
        }
        public float[] GetFloatArray(string name) 
        { 
            // получить значение массива
            JavaArray array = GetJavaArray(name); 

            // вернуть значение массива
            return (float[])(array != null ? array.Value : null); 
        }
        public double[] GetDoubleArray(string name) 
        { 
            // получить значение массива
            JavaArray array = GetJavaArray(name); 

            // вернуть значение массива
            return (double[])(array != null ? array.Value : null); 
        }
        public string[] GetStringArray (string name) 
        { 
            // получить значение массива
            JavaArray array = GetJavaArray(name); 

            // вернуть значение массива
            return (string[])(array != null ? array.Value : null); 
        }
    }
}
