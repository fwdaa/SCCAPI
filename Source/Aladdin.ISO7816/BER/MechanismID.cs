using System;
using System.IO;

namespace Aladdin.ISO7816.BER
{
    ///////////////////////////////////////////////////////////////////////////////
    // Описание идентификатора алгоритма
    ///////////////////////////////////////////////////////////////////////////////
    public class MechanismID : DataObjectTemplate
    {
        // конструктор раскодирования
        public MechanismID(TagScheme tagScheme, byte[] content)

            // сохранить переданные параметры
            : base(Authority.ISO7816, Tag.Context(0x0C, ASN1.PC.Constructed), tagScheme, content) 
        {    
            // проверить число элементов
            if (Count < 2) throw new InvalidDataException();
        
            // проверить тип первого элемента
            if (this[0].Tag != Tag.Context(0x00, ASN1.PC.Primitive)) 
            {
                // при ошибке выбросить исключение
                throw new InvalidDataException();
            }
            // для всех оставшихся элементов
            for (int i = 1; i < Count; i++)
            {
                // проверить тип элемента
                if (this[i].Tag != Tag.ObjectIdentifier)
                {
                    // при ошибке выбросить исключение
                    throw new InvalidDataException();
                }
            }
        } 
        // идентификатор алгоритма
        public byte[] Reference { get { return this[0].Content; }}

        // описание алгоритма
        public ASN1.ObjectIdentifier[] ObjectID { get
        {
            // выделить буфер требуемого размера
            ASN1.ObjectIdentifier[] objIDs = new ASN1.ObjectIdentifier[Count - 1]; 
        
            // для всех идентификаторов
            for (int i = 1; i < Count; i++) { DataObject obj = this[i]; 
            
                // раскодировать идентификатор
                objIDs[i - 1] = new ASN1.ObjectIdentifier(
                    ASN1.Encodable.Encode(obj.Tag.AsnTag, obj.Tag.PC, obj.Content)
                ); 
            }
            // вернуть идентификатор
            return objIDs; 
        }}
    }
}
