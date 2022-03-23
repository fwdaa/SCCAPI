using System;
using System.Reflection;
using System.Diagnostics.CodeAnalysis; 

namespace Aladdin.CAPI
{
    ///////////////////////////////////////////////////////////////////////////
    // Фабрика создания генераторов случайных данных с использованием GUI
    ///////////////////////////////////////////////////////////////////////////
    [SuppressMessage("Microsoft.Design", "CA1063:ImplementIDisposableCorrectly")]
    public class GuiRandFactory : RefObject, IRandFactory
    {
        // класс фабрики генераторов 
        private string className; 

        // конструктор
        public GuiRandFactory(Environment.ConfigRandFactory element, string identityString)
        {
            // сохранить переданные параметры
            className = element.Class + identityString; 
        }
        // создать генератор случайных данных
        public virtual IRand CreateRand(object window)
        {
		    // загрузить фабрику генераторов 
            using (IRandFactory factory = LoadFactory(className))
            {
                // создать генератор случайных данных
                return factory.CreateRand(window); 
            }
        }
		// загрузить фабрику генераторов 
		private IRandFactory LoadFactory(string className)
		{
			// указать режим поиска конструктора
			BindingFlags flags = BindingFlags.Instance | 
				BindingFlags.Public | BindingFlags.CreateInstance; 

			// получить описание типа
			Type type = Type.GetType(className, true); 

			// получить описание конструктора
			ConstructorInfo constructor = type.GetConstructor(
				flags, null, new Type[0], null
			); 
			// проверить наличие конструктора
			if (constructor == null) throw new TargetException();

			// загрузить объект
			try { return (IRandFactory)constructor.Invoke(new object[0]); }

            // обработать исключение
            catch (TargetInvocationException e) { throw e.InnerException; }
		}
    }
}
