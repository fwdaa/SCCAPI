using System;

namespace Aladdin.CAPI
{
    ///////////////////////////////////////////////////////////////////////////////
    // Параметры размера ключа в битах
    ///////////////////////////////////////////////////////////////////////////////
    [Serializable]
    public class KeyBitsParameters : IKeyBitsParameters
    {
        // конструктор
        public KeyBitsParameters(int keyBits) { this.keyBits = keyBits; }
    
        // размер ключа в битах
        public int KeyBits { get { return keyBits; } } private int keyBits;  
    }
}
