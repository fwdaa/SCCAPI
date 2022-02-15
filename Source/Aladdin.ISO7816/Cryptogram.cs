using System;
using System.IO;

namespace Aladdin.ISO7816
{
    ///////////////////////////////////////////////////////////////////////////////
    // Зашифрованные данные с указанием типа
    ///////////////////////////////////////////////////////////////////////////////
    public class Cryptogram 
    {
        // конструктор
        public Cryptogram(byte[] content) 
        {
            // проверить размер данных
            if (content.Length == 0) throw new InvalidDataException(); 
        
            // выделить память для данных
            Type = content[0]; Data = new byte[content.Length - 1]; 
        
            // скопировать данные
            Array.Copy(content, 1, Data, 0, Data.Length);
        }
        // конструктор
        public Cryptogram(byte type, byte[] data)
        {
            // сохранить переданные параметры
            Type = type; Data = data; 
        }
        // тип и зашифрованные данные
        public readonly byte Type; public readonly byte[] Data; 
    
        // закодированное представление
        public byte[] Encoded { get 
        {
            // выделить память для содержимого 
            byte[] encoded = new byte[1 + Data.Length]; encoded[0] = Type;
        
            // скопировать тип и зашифрованные данные
            Array.Copy(Data, 0, encoded, 1, Data.Length); return encoded; 
        }}
    }
}
