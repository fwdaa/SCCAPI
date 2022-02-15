using System;
using System.Collections.Generic;

namespace Aladdin.IO.Java
{
    ///////////////////////////////////////////////////////////////////////////
    // Значение поля класса Java
    ///////////////////////////////////////////////////////////////////////////
    public class Field
    {
        // переупорядочить список полей
        public static Field[] RearrangeFields(params Field[] fields)
        {
            // создать пустой список полей
            List<Field> list = new List<Field>(); 

            // для всех полей
            for (int i = 0; i < fields.Length; i++)
            {
                // определить имя типа
                string type = fields[i].Description.Type; 

                // добавить примитивное поле в список
                if (JavaType.IsPrimitiveType(type)) list.Add(fields[i]); 
            }
            // для всех полей
            for (int i = 0; i < fields.Length; i++)
            {
                // определить имя типа
                string type = fields[i].Description.Type; 

                // добавить составное поле в список
                if (!JavaType.IsPrimitiveType(type)) list.Add(fields[i]); 
            }
            // вернуть список полей
            return list.ToArray(); 
        }
        // описание поля и значение поля
        public readonly FieldDesc Description; public readonly object Value; 
        
        // конструктор
        internal Field(string name, string type, object value)
        {
            // сохранить переданные параметры
            Description = new FieldDesc(name, type); Value = value; 
        }
        // конструктор
        public Field(string name,  Boolean value) : this(name, "boolean"         , value) {}
        public Field(string name,    SByte value) : this(name, "byte"            , value) {}
        public Field(string name,     Byte value) : this(name, "byte"            , value) {}
        public Field(string name,    Int16 value) : this(name, "short"           , value) {}
        public Field(string name,   UInt16 value) : this(name, "short"           , value) {}
        public Field(string name,    Int32 value) : this(name, "int"             , value) {}
        public Field(string name,   UInt32 value) : this(name, "int"             , value) {}
        public Field(string name,    Int64 value) : this(name, "long"            , value) {}
        public Field(string name,   UInt64 value) : this(name, "long"            , value) {}
        public Field(string name,   Single value) : this(name, "float"           , value) {}
        public Field(string name,   Double value) : this(name, "double"          , value) {}
        public Field(string name,     Char value) : this(name, "char"            , value) {}
        public Field(string name,   String value) : this(name, "java.lang.String", value) {} 
        public Field(string name, DateTime value) : this(name, "java.util.Date"  , value) {}

        // конструктор
        public Field(string name, JavaObject value) : this(name, value.Type.Name, value) {} 
        public Field(string name, JavaArray  value) : this(name, value.Type.Name, value) {} 

        // конструктор
        public Field(string name,  Boolean[] value) : this(name, "[Z", new JavaArray(value)) {} 
        public Field(string name,    SByte[] value) : this(name, "[B", new JavaArray(value)) {} 
        public Field(string name,     Byte[] value) : this(name, "[B", new JavaArray(value)) {} 
        public Field(string name,    Int16[] value) : this(name, "[S", new JavaArray(value)) {} 
        public Field(string name,   UInt16[] value) : this(name, "[S", new JavaArray(value)) {} 
        public Field(string name,    Int32[] value) : this(name, "[I", new JavaArray(value)) {} 
        public Field(string name,   UInt32[] value) : this(name, "[I", new JavaArray(value)) {} 
        public Field(string name,    Int64[] value) : this(name, "[J", new JavaArray(value)) {} 
        public Field(string name,   UInt64[] value) : this(name, "[J", new JavaArray(value)) {} 
        public Field(string name,   Single[] value) : this(name, "[F", new JavaArray(value)) {} 
        public Field(string name,   Double[] value) : this(name, "[D", new JavaArray(value)) {} 
        public Field(string name,     Char[] value) : this(name, "[C", new JavaArray(value)) {} 
        public Field(string name,   String[] value)
        
            // сохранить переданные параметры
            : this(name, "[Ljava.lang.String;", new JavaArray(value)) {} 
        
        public Field(string name, DateTime[] value) 
            
            // сохранить переданные параметры
            : this(name, "[Ljava.util.Date;", new JavaArray(value)) {} 

        // имя поля
        public string Name { get { return Description.Name; } }
    }
}
