using System; 
using System.Collections.Generic; 
using System.Reflection; 
using System.ComponentModel;

namespace Aladdin.CAPI.GUI
{
    public static class Reflection
    {
        ///////////////////////////////////////////////////////////////////////
        // Получить описание значения перечисления
        ///////////////////////////////////////////////////////////////////////
        public static string GetDescription<T>(T enumerationValue) where T : struct
        {
            // создать список значений
            List<String> parts = new List<String>(); 

            // получить тип значения 
            Type type = enumerationValue.GetType(); 

            // для всех значений из представления
            foreach (string part in enumerationValue.ToString().Split(','))
            {
                // получить описание значения
                string name = part.Trim(); MemberInfo[] memberInfo = type.GetMember(name);

                // проверить наличие описания значения
                if (memberInfo == null || memberInfo.Length == 0) parts.Add(name); 
                else {
                    // получить атрибуты значения
                    object[] attrs = memberInfo[0].GetCustomAttributes(
                        typeof(DescriptionAttribute), false
                    );
                    // проверить наличие атрибута
                    if (attrs == null || attrs.Length == 0) parts.Add(name); 
                    
                    // сохранить значение атрибута
                    else parts.Add(((DescriptionAttribute)attrs[0]).Description);
                }
            }
            // объединить части
            return String.Join(", ", parts.ToArray()); 
        }
    }
}
