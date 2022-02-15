using System;
using System.IO;

namespace Aladdin.IO.Java
{
    ///////////////////////////////////////////////////////////////////////////
    // Описание класса Java
    ///////////////////////////////////////////////////////////////////////////
    public class ClassDesc
    {
        // допустимые флаги
        public const byte SC_WRITE_METHOD = 0x1; 
        public const byte SC_SERIALIZABLE = 0x2; 

        // раскодировать описание класса
        public static ClassDesc Decode(SerialStream stream,
            byte[] encoded, int offset, int length, out int size) 
        {
            // проверить корректность данных
            if (length < 1) throw new InvalidDataException(); size = 1; 

            // проверить корректность данных
            if (encoded[offset] != 0x72) throw new InvalidDataException(); 

            // пропустить заголовок
            int next = size; offset += size; length -= size; 

            // зарезервировать слот в списке
            int index = stream.Objects.Count; stream.Objects.Add(null); 

            // раскодировать имя типа 
            string name = stream.DecodeName(encoded, offset, length, out next); 

            // перейти на следующее поле
            size += next; offset += next; length -= next;

            // раскодировать серийный номер
            long serialUID = stream.DecodeLong(encoded, offset, length, out next); 

            // перейти на следующее поле
            size += next; offset += next; length -= next;

            // проверить корректность размера
            if (length < 1) throw new InvalidDataException(); next = 1; 

            // прочитать флаги
            byte flags = encoded[offset]; 

            // перейти на следующее поле
            size += next; offset += next; length -= next;

            // раскодировать число полей
            short count = stream.DecodeShort(encoded, offset, length, out next); 

            // перейти на следующее поле
            size += next; offset += next; length -= next;

            // выделить массив для полей
            FieldDesc[] fields = new FieldDesc[count]; 

            // для всех полей
            for (int i = 0; i < count; i++)
            {
                // раскодировать описание поля
                fields[i] = FieldDesc.Decode(stream, encoded, offset, length, out next); 

                // перейти на следующее поле
                size += next; offset += next; length -= next;
            }
            // проверить корректность размера
            if (length < 1) throw new InvalidDataException(); next = 1; 

            // проверить корректность данных
            if (encoded[offset] != 0x78) throw new InvalidDataException();

            // перейти на следующее поле
            size += next; offset += next; length -= next;

            // раскодировать описание базового класса
            ClassDesc parentDesc = stream.DecodeClassDesc(encoded, offset, length, out next); 

            // перейти на следующее поле
            size += next; offset += next; length -= next;

            // создать описание класса
            ClassDesc classDesc = new ClassDesc(name, serialUID, flags, parentDesc, fields); 

            // добавить описание класса в список
            stream.Objects[index] = classDesc; return classDesc; 
        }
        // имя типа и серийный неомер
        public readonly string Name; public readonly long SerialUID; public readonly byte Flags; 
        
        // родительский тип и описание полей
        public readonly ClassDesc ParentDesc; public readonly FieldDesc[] Fields; 

        // конструктор
        public ClassDesc(string name, long serialUID, byte flags, 
            ClassDesc parentDesc, params FieldDesc[] fields)
        { 
            // сохранить переданные параметры
            Name = name; SerialUID = serialUID; Flags = flags; 

            // проверить возможность сериализации
            if ((flags & SC_SERIALIZABLE) == 0) throw new InvalidDataException();

            // сохранить переданные параметры
            ParentDesc = parentDesc; Fields = fields; 
        } 
        // закодировать значение
        public byte[] Encode(SerialStream stream)
        {
            // определить число полей
            short fieldCount = (short)Fields.Length; stream.Objects.Add(this); 

            // закодировать имя класса, серийный номер и число полей
            byte[] encodedName   = stream.EncodeName (Name      );
            byte[] encodedSerial = stream.EncodeLong (SerialUID ); 
            byte[] encodedSize   = stream.EncodeShort(fieldCount); 

            // инициализировать общий размер
            int total = 3 + encodedName.Length + encodedSerial.Length + encodedSize.Length;
            
            // создать список закодированных полей
            byte[][] encodedFields = new byte[Fields.Length][]; 

            // для всех полей
            for (int i = 0; i < Fields.Length; i++)
            {
                // закодировать описание поля
                encodedFields[i] = Fields[i].Encode(stream); 
                
                // увеличить общий размер
                total += encodedFields[i].Length; 
            }
            // закодировать родительский класс
            byte[] encodedParent = stream.EncodeClassDesc(ParentDesc); 

            // увеличить общий размер
            total += encodedParent.Length; 

            // выделить буфер требуемого размера
            byte[] encoded = new byte[total]; encoded[0] = 0x72; total = 1; 

            // скопировать имя класса
            Array.Copy(encodedName, 0, encoded, total, encodedName.Length); 
            
            // перейти на следующее поле
            total = total + encodedName.Length; 

            // скопировать серийный номер
            Array.Copy(encodedSerial, 0, encoded, total, encodedSerial.Length); 

            // перейти на следующее поле
            total = total + encodedSerial.Length; encoded[total++] = Flags;

            // закодировать число полей
            Array.Copy(encodedSize, 0, encoded, total, encodedSize.Length); 

            // перейти на следующее поле
            total = total + encodedSize.Length; 

            // для всех полей
            for (int i = 0; i < encodedFields.Length; i++)
            {
                // скопировать закодированное поле
                Array.Copy(encodedFields[i], 0, encoded, total, encodedFields[i].Length); 
                
                // перейти на следующее поле
                total += encodedFields[i].Length; 
            }
            // установить разделитель TC_ENDBLOCKDATA
            encoded[total++] = 0x78; 

            // скопировать родительский класс
            Array.Copy(encodedParent, 0, encoded, total, encodedParent.Length); return encoded;
        }
    }
}
