using System;
using System.IO;

namespace Aladdin.IO.Java
{
    ///////////////////////////////////////////////////////////////////////////
    // Описание типа Java
    ///////////////////////////////////////////////////////////////////////////
    public abstract class JavaType
    {
        // имя типа и декорированное имя типа
        public abstract string Name { get; } public abstract string DecoratedName { get; } 

        // закодировать значение
        public abstract byte[] Encode(SerialStream stream, object value); 

        // выполнить декорирование имени
        public static string DecorateType(string name)
        {
            // вернуть имя типа массива
            if (name.StartsWith("[")) return name; 

            // выполнить декорирование имени
            if (name == "boolean") return "Z"; 
            if (name == "byte"   ) return "B"; 
            if (name == "short"  ) return "S"; 
            if (name == "int"    ) return "I"; 
            if (name == "long"   ) return "J"; 
            if (name == "float"  ) return "F"; 
            if (name == "double" ) return "D"; 
            if (name == "char"   ) return "C"; 

            // вернуть тип объекта
            return String.Format("L{0};", name.Replace('.', '.')); 
        }
        // выполнить раздекорирование имени
        public static string UndecorateType(string name)
        {
            // вернуть имя типа массива
            if (name.StartsWith("[")) return name; 

            // проверить корректность данных
            if (name.Length == 1) switch (name[0])
            {
            // вернуть имя примтивного типа
            case 'Z': return "boolean";
            case 'B': return "byte"   ;
            case 'S': return "short"  ;
            case 'I': return "int"    ;
            case 'J': return "long"   ;
            case 'F': return "float"  ;
            case 'D': return "double" ;
            case 'C': return "char"   ;
            }
            // проверить корректность данных
            if (!name.StartsWith("L") || !name.EndsWith(";"))
            {
                // при ошибке выбросить исключение
                throw new InvalidDataException(); 
            }
            // выполнить раздекорирование имени
            return name.Substring(1, name.Length - 2).Replace('.', '.'); 
        }
        // признак примитивного типа
        public static bool IsPrimitiveType(string name)
        {
            if (name == "boolean") return true; 
            if (name == "byte"   ) return true; 
            if (name == "short"  ) return true; 
            if (name == "int"    ) return true; 
            if (name == "long"   ) return true; 
            if (name == "float"  ) return true; 
            if (name == "double" ) return true; 
            if (name == "char"   ) return true; 

            return false; 
        }
    }
}
