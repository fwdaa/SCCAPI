using System;
using System.IO;
using System.Xml;

namespace Aladdin.CAPI.Environment
{
    ///////////////////////////////////////////////////////////////////////////
    // Элемент расширения
    ///////////////////////////////////////////////////////////////////////////
    [Serializable]
    public class ConfigPlugin 
    {
        // имя плагина и класса плагина
        private string name; private string className; 
        // размер salt-значения и число итераций
        private string pbmSaltLength; private string pbmIterations; 
        private string pbeSaltLength; private string pbeIterations; 
    
        // конструктор
        public ConfigPlugin(XmlElement element) 
        {
            // получить имя элемента 
            name = element.GetAttribute("name"); 
            // проверить наличие имени элемента
            if (name.Length == 0) throw new IOException(); 
        
            // получить класс расширения
            className = element.GetAttribute("class"); 

            // получить размер salt-значения
            pbmSaltLength = element.GetAttribute("pbmSaltLength"); 
            // проверить наличие размера 
            if (pbmSaltLength.Length == 0) throw new IOException(); 
        
            // получить число итераций
            pbmIterations = element.GetAttribute("pbmIterations"); 
            // проверить наличие числа итераций
            if (pbmIterations.Length == 0) throw new IOException(); 
        
            // получить размер salt-значения
            pbeSaltLength = element.GetAttribute("pbeSaltLength"); 
            // проверить наличие размера 
            if (pbeSaltLength.Length == 0) throw new IOException(); 
        
            // получить число итераций
            pbeIterations = element.GetAttribute("pbeIterations"); 
            // проверить наличие числа итераций
            if (pbeIterations.Length == 0) throw new IOException(); 
        }
        // имя плагина
        public string Name { get { return name; }}
        // имя класса
        public string Class { get { return className; }}
    
        // размер salt-значения
        public int PBMSaltLength { get { return Int32.Parse(pbmSaltLength); }}
        // число итераций
        public int PBMIterations { get { return Int32.Parse(pbmIterations); }}
        // размер salt-значения
        public int PBESaltLength { get { return Int32.Parse(pbeSaltLength); }}
        // число итераций
        public int PBEIterations { get { return Int32.Parse(pbeIterations); }}
    }
}
