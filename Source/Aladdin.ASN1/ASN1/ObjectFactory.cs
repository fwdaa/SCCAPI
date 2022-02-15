using System;
using System.Reflection;
using System.IO;

namespace Aladdin.ASN1
{
	///////////////////////////////////////////////////////////////////////////
	// Фабрика создания объекта для конкретного типа
	///////////////////////////////////////////////////////////////////////////
	public class ObjectFactory<T> : IObjectFactory<T> where T : IEncodable
	{
        // методы проверки корректности типа
        private MethodInfo tagValidator;  

        // методы проверки корректности объекта
        private MethodInfo objValidator; private object[] args; 

		// конструктор
		public ObjectFactory(params object[] args)
		{
			// указать режим поиска
			BindingFlags flags = BindingFlags.Public | BindingFlags.Static | 
				BindingFlags.FlattenHierarchy | BindingFlags.InvokeMethod; 

			// указать типы аргументов
			Type[] types = new Type[] { typeof(Tag) }; this.args = args; 

			// найти соответствующий метод
			tagValidator = typeof(T).GetMethod("IsValidTag", flags, null, types, null);
  
			// проверить отсутствие ошибок
			if (tagValidator == null) throw new TargetException(); 

		    // выделить память для типов аргументов
            if (args.Length > 0) { types = new Type[args.Length + 2]; 

                // указать типы аргументов
                types[0] = typeof(T); types[1] = typeof(bool);
        
			    // указать типы аргументов
			    for (int i = 0; i < args.Length; i++) types[i + 2] = args[i].GetType();
 
			    // найти соответствующий метод
			    objValidator = typeof(T).GetMethod("Validate", flags, null, types, null);

			    // проверить отсутствие ошибок
			    if (objValidator == null) throw new TargetException(); 
            }
		}
		// проверить допустимость типа
		public bool IsValidTag(Tag tag) 
        { 
            // указать параметры вызова
            object[] parameters = new object[] { tag }; 

			// проверить допустимость типа
			try { return (bool)tagValidator.Invoke(null, parameters); } 

            // обработать исключение
            catch (TargetInvocationException e) { throw e.InnerException; }
        }
		// проверить корректность объекта
		void IObjectFactory.Validate(IEncodable encodable, bool encode) 
		{ 
			// проверить корректность объекта
			if (!(encodable is T)) 
            {
			    // выбросить исключение 
			    if (encode) throw new ArgumentException(); 

			    // выбросить исключение 
                else throw new InvalidDataException(); 
            }
			// проверить корректность объекта
			((IObjectFactory<T>)this).Validate((T)encodable, encode); 
		} 
		// проверить корректность объекта
		public virtual void Validate(T encodable, bool encode) 
		{
			// проверить необходимость обработки
			if (objValidator == null) return; 

            // указать параметры вызова
            object[] parameters = Arrays.Concat(new object[] { encodable, encode }, args); 

    		// проверить корректность объекта
			try { objValidator.Invoke(null, parameters); }

            // обработать исключение
            catch (TargetInvocationException e) { throw e.InnerException; }
		} 
		// получить информацию кодирования
		IEncodable IObjectFactory.Decode(IEncodable encodable) 
		{ 
			// раскодировать объект
			return ((IObjectFactory<T>)this).Decode(encodable); 
		}
		// раскодировать 
		public virtual T Decode(IEncodable encodable) 
		{ 
			// указать параметры конструктора
			Type[] types = new Type[] { typeof(IEncodable) }; 

			// найти соответствующий конструктор
			ConstructorInfo constructor = typeof(T).GetConstructor(types);  
            try { 
			    // вызвать конструктор
			    T obj = (T)constructor.Invoke(new object[] {encodable});

			    // проверить корректность
			    ((IObjectFactory)this).Validate(obj, false); return obj; 
            }
            // обработать исключение
            catch (TargetInvocationException e) { throw e.InnerException; }
		} 
	}
}
