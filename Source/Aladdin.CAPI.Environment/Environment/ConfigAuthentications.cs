using System;
using System.Xml;

namespace Aladdin.CAPI.Environment
{
    ///////////////////////////////////////////////////////////////////////////
    // Элемент описания аутентификаций
    ///////////////////////////////////////////////////////////////////////////
    [Serializable]
    public class ConfigAuthentications 
    {
        // число попыток аутентификации 
        private string attempts; 
    
        // конструктор
        public ConfigAuthentications(XmlElement element)
        {
            // получить число попыток аутентификации
            attempts = element.GetAttribute("attempts"); 
        }
        // число попыток аутентификации 
        public int Attempts { get 
        { 
            // число попыток аутентификации 
            return (attempts.Length > 0) ? Int32.Parse(attempts) : 5; 
        }}
    }
}
