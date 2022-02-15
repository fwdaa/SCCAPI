using System;

namespace Aladdin.IO.Java
{
    ///////////////////////////////////////////////////////////////////////////
    // Описание массива Java
    ///////////////////////////////////////////////////////////////////////////
    public class JavaArray
    {
        // тип объекта и cодержимое объекта
        public readonly ArrayType Type; public readonly Array Value;

        // конструктор
        public JavaArray(ArrayType type, Array value) { Type = type; Value = value; }

        // конструктор
        public JavaArray(string name, long serialUID, Array value) 
            
            // сохранить переданные параметры
            : this(new ArrayType(name, serialUID), value) {}

        // конструктор
        public JavaArray(Boolean[] value) : this("[Z", ArrayType.BooleanArrayUID, value) {}
        public JavaArray(  SByte[] value) : this("[B", ArrayType.ByteArrayUID   , value) {}
        public JavaArray(   Byte[] value) : this("[B", ArrayType.ByteArrayUID   , value) {}
        public JavaArray(  Int16[] value) : this("[S", ArrayType.ShortArrayUID  , value) {}
        public JavaArray( UInt16[] value) : this("[S", ArrayType.ShortArrayUID  , value) {}
        public JavaArray(  Int32[] value) : this("[I", ArrayType.IntegerArrayUID, value) {}
        public JavaArray( UInt32[] value) : this("[I", ArrayType.IntegerArrayUID, value) {}
        public JavaArray(  Int64[] value) : this("[J", ArrayType.LongArrayUID   , value) {}
        public JavaArray( UInt64[] value) : this("[J", ArrayType.LongArrayUID   , value) {}
        public JavaArray( Single[] value) : this("[F", ArrayType.FloatArrayUID  , value) {}
        public JavaArray( Double[] value) : this("[D", ArrayType.DoubleArrayUID , value) {}
        public JavaArray(   Char[] value) : this("[C", ArrayType.CharArrayUID   , value) {}
        public JavaArray( String[] value) 
        
            // сохранить переданные параметры
            : this("[Ljava.lang.String;", ArrayType.StringArrayUID, value) {}

        public JavaArray(DateTime[] value) 
        
            // сохранить переданные параметры
            : this("[Ljava.util.Date;", ArrayType.DateArrayUID, value) {}
    }
}
