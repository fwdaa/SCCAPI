using System;
using System.IO;
using System.Collections.Generic;

namespace Aladdin.ISO7816
{
    ///////////////////////////////////////////////////////////////////////////
    // Байты предыстории
    ///////////////////////////////////////////////////////////////////////////
    public class HistoricalBytes : CardEnvironment
    {
        // используемые объекты и закодированное представление
        private List<DataObject> objects; private byte[] encoded; 
    
        // конструктор
        public HistoricalBytes(byte[] encoded, int offset, int length) : base(TagScheme.Default)
        {
            // проверить корректность данных
            if (length < 1) throw new InvalidDataException(); 

            // скопировать представление
            this.objects = new List<DataObject>(); this.encoded = new byte[length]; 
            
            // скопировать представление
            Array.Copy(encoded, offset, this.encoded, 0, length);

            // для стандартного формата
            if (encoded[offset] == 0x00 || encoded[offset] == 0x80)
            {
                // для всех объектов
                for (int index = 1; index < length; )
                {
                    // для непоследнего элемента
                    if (encoded[offset] == 0x80 || index < length - 3)
                    {
                        // раскодировать объект
                        CompactTLV obj = new CompactTLV(
                            encoded, offset + index, length - index
                        ); 
                        // перейти на следующий элемент
                        objects.Add(obj.ToObject()); index += obj.Encoded.Length;
                    }
                    else { byte[] value = new byte[3];

                        // извлечь значение
                        Array.Copy(encoded, offset + index, value, 0, length - index); 

                        // закодировать объект
                        CompactTLV obj = new CompactTLV(Tag.LifeCycle, value); 

                        // перейти на следующий элемент
                        objects.Add(obj.ToObject()); index = length; 
                    }
                }
            }
        }
	    // перечислитель объектов
        public override IEnumerator<DataObject> GetEnumerator() 
        { 
	        // перечислитель объектов
            return objects.GetEnumerator(); 
        }
        // закодированное представление
        public byte[] Encoded { get { return encoded; }}
    }
}
