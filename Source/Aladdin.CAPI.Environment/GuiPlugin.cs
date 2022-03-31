﻿using System;
using System.Reflection;
using System.Diagnostics.CodeAnalysis; 

namespace Aladdin.CAPI
{
    ///////////////////////////////////////////////////////////////////////////
    // Элемент расширения с использованием GUI
    ///////////////////////////////////////////////////////////////////////////
    [SuppressMessage("Microsoft.Design", "CA1063:ImplementIDisposableCorrectly")]
    public class GuiPlugin : RefObject, ICulturePlugin
    {
        // класс плагина и параметры шифрования по паролю
        private string className; private PBE.PBEParameters pbeParameters; 

        // конструктор
        public GuiPlugin(Environment.ConfigPlugin element, string identityString) 
        {
            // получить класс расширения
            className = element.Class; if (!String.IsNullOrEmpty(className))
            {
                // указать строку идентификации
                className += identityString; 
            }
            // создать параметры шифрования по паролю
            pbeParameters = new PBE.PBEParameters(
                element.PBMSaltLength, element.PBMIterations, 
                element.PBESaltLength, element.PBEIterations 
            ); 
        }
        // параметры шифрования по паролю
        public PBE.PBEParameters PBEParameters { get { return pbeParameters; }} 

        // параметры ключа
        public IParameters GetKeyParameters(IRand rand, string keyOID, KeyUsage keyUsage)
        {
            // проверить наличие имени класса
            if (String.IsNullOrEmpty(className)) throw new NotSupportedException(); 

            // загрузить плагин
            using (ICulturePlugin plugin = LoadPlugin(className))
            { 
                // получить параметры ключа
                return plugin.GetKeyParameters(rand, keyOID, keyUsage); 
            }
        }
        // параметры шифрования по паролю
        public PBE.PBECulture GetPBECulture(object window, string keyOID)
        {
            // проверить наличие имени класса
            if (String.IsNullOrEmpty(className)) throw new NotSupportedException(); 

            // загрузить плагин
            using (ICulturePlugin plugin = LoadPlugin(className))
            { 
                // получить параметры шифрования по паролю
                return plugin.GetPBECulture(window, keyOID); 
            }
        }
		// загрузить плагин
		private ICulturePlugin LoadPlugin(string className)
		{
			// указать режим поиска конструктора
			BindingFlags flags = BindingFlags.Instance | 
				BindingFlags.Public | BindingFlags.CreateInstance; 

			// получить описание типа
			Type type = Type.GetType(className, true); 

			// получить описание конструктора
			ConstructorInfo constructor = type.GetConstructor(
				flags, null, new Type[] { typeof(PBE.PBEParameters) }, null
			); 
			// проверить наличие конструктора
			if (constructor == null) throw new TargetException();

			// загрузить объект
			try { return (ICulturePlugin)constructor.Invoke(new object[] { pbeParameters }); }

            // обработать исключение
            catch (TargetInvocationException e) { throw e.InnerException; }
		}
    }
}