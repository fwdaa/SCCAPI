using System;
using System.Collections.Generic;
using System.Reflection;

namespace Aladdin.CAPI.SCard
{
    ///////////////////////////////////////////////////////////////////////////
    // Параметры форматирования апплетов
    ///////////////////////////////////////////////////////////////////////////
    public class FormatParameters 
    {
        // конструктор
        public FormatParameters(int ordinal) { this.ordinal = ordinal; } 
        // конструктор
        public FormatParameters() : this(0) {} private int ordinal; 
        
        // перечислить параметры 
        public KeyValuePair<String, IFormatParameter>[] Enumerate()
        {
            // создать список параметров
            List<KeyValuePair<String, IFormatParameter>> list = 
                new List<KeyValuePair<String, IFormatParameter>>(); 

            // для всех полей
            foreach (FieldInfo field in GetType().GetFields())
            {
                // для вложенных параметров
                if (typeof(FormatParameters).IsAssignableFrom(field.FieldType))
                {
                    // получить значение параметров
                    FormatParameters inners = (FormatParameters)field.GetValue(this); 

                    // для всех внутренних параметров
                    foreach (KeyValuePair<String, IFormatParameter> item in inners.Enumerate())
                    {
                        // сформировать составное имя
                        String name = String.Format("{0}.{1}", field.Name, item.Key); 

                        // создать элемент для вставки
                        KeyValuePair<String, IFormatParameter> insertItem = 
                            new KeyValuePair<String, IFormatParameter>(name, item.Value); 

                        // для всех элементов списка
                        bool inserted = false; for (int i = 0; i < list.Count; i++)
                        {
                            // проверить полрядковый номер
                            if (list[i].Value.Ordinal > inners.ordinal) 
                            { 
                                // вставить элемент в список
                                list.Insert(i, insertItem); inserted = true; break; 
                            }
                        }
                        // добавить элемент
                        if (!inserted) list.Add(insertItem); 
                    }
                }
                // проверить тип поля
                else if (typeof(IFormatParameter).IsAssignableFrom(field.FieldType))
                {
                    // получить значение поля
                    IFormatParameter parameter = (IFormatParameter)field.GetValue(this);

                    // создать элемент для вставки
                    KeyValuePair<String, IFormatParameter> insertItem = 
                       new KeyValuePair<String, IFormatParameter>(field.Name, parameter); 

                    // для всех элементов списка
                    bool inserted = false; for (int i = 0; i < list.Count; i++)
                    {
                        // проверить полрядковый номер
                        if (list[i].Value.Ordinal > parameter.Ordinal) 
                        { 
                            // вставить элемент в список
                            list.Insert(i, insertItem); inserted = true; break; 
                        }
                    }
                    // добавить элемент
                    if (!inserted) list.Add(insertItem); 
                }
            }
            return list.ToArray(); 
        }
        // установить значение параметра
        public void SetParameter(string name, string value)
        {
            // найти позицию разделителя
            int position = name.IndexOf('.'); if (position >= 0)
            {
                // найти поле с указанным именем
                FieldInfo field = GetType().GetField(name.Substring(0, position)); 

                // проверить наличие поля
                if (field == null) throw new ArgumentException(); 

                // проверить тип поля
                if (!typeof(FormatParameters).IsAssignableFrom(field.FieldType))
                {
                    // при ошибке выбросить исключение
                    throw new ArgumentException(); 
                }
                // получить значение поля
                FormatParameters inners = (FormatParameters)field.GetValue(this); 

                // установить значение параметра
                inners.SetParameter(name.Substring(position + 1), value); 
            }
            else { 
                // найти поле с указанным именем
                FieldInfo field = GetType().GetField(name); 

                // проверить наличие поля
                if (field == null) throw new ArgumentException(); 

                // проверить тип поля
                if (!typeof(IFormatParameter).IsAssignableFrom(field.FieldType))
                {
                    // при ошибке выбросить исключение
                    throw new ArgumentException(); 
                }
                // установить значение параметра
                ((IFormatParameter)field.GetValue(this)).Value = value; 
            }
        }
    }
}
