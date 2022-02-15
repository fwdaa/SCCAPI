using System;
using System.Runtime.InteropServices;
using System.Diagnostics.CodeAnalysis;

namespace Aladdin.CAPI.COM
{
    ///////////////////////////////////////////////////////////////////////////
    // Отличимое имя
    ///////////////////////////////////////////////////////////////////////////
    [ClassInterface(ClassInterfaceType.None)]
    public class DistinctName : IDistinctName
    {
        // строковое и бинарное представление 
        private string name; private string encoded; 

        // конструктор
        public DistinctName(string name, byte[] encoded)
        {
            // сохранить переданные параметры
            this.name = name; this.encoded = Convert.ToBase64String(encoded); 
        }
        // строковое представление 
        public override string ToString() { return name; }

        // бинарное представление 
        public string Encoded { get { return encoded; }}
    }
}
