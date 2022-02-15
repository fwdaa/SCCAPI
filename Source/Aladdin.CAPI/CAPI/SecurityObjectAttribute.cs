using System; 
using System.Reflection; 

namespace Aladdin.CAPI
{
    ///////////////////////////////////////////////////////////////////////////
    // Атрибут необходимости аутентификации при вызове метода
    ///////////////////////////////////////////////////////////////////////////
    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Struct, AllowMultiple = false)] 
    public class SecurityObjectAttribute : Attribute
    {
        // конструктор
        public SecurityObjectAttribute(string name) { this.name = name; } private string name; 
        
        // защищаемый объект
        public SecurityObject GetObject(object reference)
        {
            // указать способ поиска поля
            BindingFlags flags = BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance; 

            // определить класс объекта
            Type classType = reference.GetType(); 
            do {
                // получить описание поля
                FieldInfo fieldInfo = classType.GetField(name, flags | BindingFlags.GetField); 

                // получить значение поля
                if (fieldInfo != null) return (SecurityObject)fieldInfo.GetValue(reference); 

                // получить описание свойства
                PropertyInfo propertyInfo = classType.GetProperty(name, flags | BindingFlags.GetProperty); 

                // получить значение свойства
                if (propertyInfo != null) return (SecurityObject)propertyInfo.GetValue(reference, null); 

                // перейти на базовый класс
                classType = classType.BaseType; 
            }
            // при ошибке выбросить исключение
            while (classType != null); throw new NotFoundException(); 
        }
    }
}
