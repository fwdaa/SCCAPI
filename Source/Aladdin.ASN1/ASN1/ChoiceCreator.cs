using System;
using System.Reflection;

namespace Aladdin.ASN1
{
	///////////////////////////////////////////////////////////////////////////
	// Фабрика создания фабрик альтернатив
	///////////////////////////////////////////////////////////////////////////
	public class ChoiceCreator<T> where T : IObjectFactory, new()
	{
		// экземпляр фабрики по умолчанию
		public IObjectFactory Factory() { return new T(); }

		// экземпляр фабрики
		public T Factory(params object[] args) 
		{
			// выделить память для типов аргументов
			Type[] types = new Type[args.Length];  

			// указать типы аргументов
			for (int i = 0; i < args.Length; i++) types[i] = args[i].GetType();
 
			// найти соответствующий конструктор
			ConstructorInfo constructor = typeof(T).GetConstructor(types);  

			// вызвать конструктор
			try { return (T)constructor.Invoke(args); }

            // обработать исключение конструктора
            catch (TargetInvocationException e) { throw e.InnerException; }
		}
	}
}
