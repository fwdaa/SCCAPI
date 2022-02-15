using System;
using System.IO;
using System.Collections.Generic;

namespace Aladdin.ISO7816
{
    ///////////////////////////////////////////////////////////////////////////
    // Расширенный заголовок
    ///////////////////////////////////////////////////////////////////////////
    public class ExtendedHeader
    {
        // заголовок объекта и внутренние объекты
        public readonly Header Header; public readonly ExtendedHeader[] Children;

        // закодировать объекты
        public static byte[] Encode(ExtendedHeader[] headers)
        {
            // выделить память для закодированных представлений
            byte[][] encodeds = new byte[headers.Length][];  

            // для всех заголовков
            for (int i = 0; i < headers.Length; i++) 
            {
                // получить закодированное представление
                encodeds[i] = headers[i].Encoded;
            }
            // объединить закодированные представления
            return Arrays.Concat(encodeds); 
        }
        // раскодировать объекты
        public static ExtendedHeader[] Decode(byte[] content, int offset, int length)
        {
            // создать пустой список заголовков
            List<ExtendedHeader> headers = new List<ExtendedHeader>(); 
        
            // для всех внутренних объектов
            for (int index = 0; index < length; )
            { 
                // раскодировать заголовок
                Header header = Header.Decode(content, offset + index, length - index); 

                // для примитивного типа
                if (header.Tag.PC == ASN1.PC.Primitive)
                {
                    // выполнить преобразование типа
                    headers.Add(new ExtendedHeader(header.Tag, header.Length)); 

                    // перейти на следующий заголовок
                    index += header.Encoded.Length;
                }
                // при отсутствии внутренних объектов
                else if (header.Length == 0x00 || header.Length == 0x80)
                {
                    // выполнить преобразование типа
                    headers.Add(new ExtendedHeader(header.Tag, header.Length)); 

                    // перейти на следующий заголовок
                    index += header.Encoded.Length;
                }
                else { 
                    // раскодировать внутренние элементы
                    ExtendedHeader[] children = Decode(
                        content, offset + index + header.Encoded.Length, header.Length
                    ); 
                    // добавить составной расширенный заголовок
                    headers.Add(new ExtendedHeader(header, children));

                    // перейти на следующий заголовок
                    index += header.Encoded.Length + header.Length;
                }
            }
            return headers.ToArray(); 
        }
        // конструктор закодирования
        public ExtendedHeader(Tag asnTag, int length) 
        {
            // проверить тип объекта
            if (asnTag.PC == ASN1.PC.Constructed) 
            {
                // проверить указанный размер
                if (length != 0x00 && length != 0x80) throw new ArgumentException();
            }
            // указать заголовок объекта
            Header = new Header(asnTag, length); 

            // указать отсутствие внутренних элементов
            Children = new ExtendedHeader[0]; 
        }
        // конструктор закодирования
        public ExtendedHeader(Tag asnTag, ExtendedHeader[] children)
        {
            // проверить тип объекта
            if (asnTag.PC != ASN1.PC.Constructed) throw new InvalidDataException(); 

            // закодировать внутреннее содержимое
            byte[] content = ExtendedHeader.Encode(children); 
        
            // указать заголовок объекта
            Header = new Header(asnTag, content.Length); Children = children; 
        }
        // конструктор раскодирования
        private ExtendedHeader(Header header, ExtendedHeader[] children)
        { 
            // проверить тип объекта
            if (header.Tag.PC != ASN1.PC.Constructed) throw new InvalidDataException(); 

            // сохранить переданные параметры
            Header = header; Children = children;
        }
        // закодировать объект
        public byte[] Encoded { get
        {
            // закодировать примитивный объект
            if (Header.Tag.PC == ASN1.PC.Primitive) return Header.Encoded; 

            // обработать отсутствие внутренних объектов
            if (Header.Length == 0x00 || Header.Length == 0x80) return Header.Encoded; 

            // закодировать внутреннее содержимое
            byte[] content = ExtendedHeader.Encode(Children); 

            // закодировать внутренние объекты
            return ASN1.Encodable.Encode(Header.Tag.AsnTag, Header.Tag.PC, content).Encoded; 
        }}
        // извлечь требуемые поля из объекта
        public ASN1.IEncodable Apply(ASN1.IEncodable encodable) 
        {
            // проверить соответствие примитивного элемента
            if (Header.Tag.PC == ASN1.PC.Primitive) return Header.Apply(encodable); 
            
            // получить тип представления
            Tag tag = new Tag(encodable.Tag, encodable.PC); 
            
            // проверить совпадение типа и игнорирование объекта
            if (Header.Tag != tag || Header.Length == 0x00) return null; 

            // проверить указание структуры
            if (Header.Length == 0x80) return encodable; byte[] content = encodable.Content;
            
            // создать список закодированных представлений
            List<byte[]> encodeds = new List<byte[]>(); 
            
            // для всех внутренних заголовков
            for (int i = 0, position = 0; i < Children.Length; i++)
            {
                // для всех внутренних объектов
                for (int offset = position; offset < content.Length; )
                { 
                    // раскодировать закодированное представление
                    ASN1.IEncodable inner = ASN1.Encodable.Decode(content, offset, content.Length - offset); 

                    // перейти на следующий объект
                    offset += inner.Encoded.Length; tag = new Tag(inner.Tag, inner.PC);
                
                    // проверить совпадение типа
                    if (Children[i].Header.Tag != tag) continue; position = offset; 
                    
                    // извлечь требуемые поля из объекта
                    ASN1.IEncodable matched = Children[i].Apply(inner); 
                    
                    // добавить представление в список
                    if (matched != null) encodeds.Add(matched.Encoded); break;
                }
            }
            // объединить закодированные представления
            content = Arrays.Concat(encodeds.ToArray()); 
            
            // закодировать объект
            return ASN1.Encodable.Encode(encodable.Tag, encodable.PC, content); 
        }
        // извлечь закодированное представление из данных
        public ASN1.IEncodable DecodeString(TagScheme tagScheme, byte[] encoded, ref int offset)
        {
            // для примитивного элемента
            if (Header.Tag.PC == ASN1.PC.Primitive)
            {
                // проверить размер данных
                if (offset + Header.Length > encoded.Length) throw new InvalidDataException(); 

                // выделить память для закодированного представления
                byte[] buffer = new byte[Header.Length]; 

                // скопировать значение
                Array.Copy(encoded, offset, buffer, 0, Header.Length); offset += Header.Length; 

                // вернуть закодированное представление
                return ASN1.Encodable.Encode(Header.Tag.AsnTag, Header.Tag.PC, buffer); 
            }
            else { 
                // проигнорировать объект
                if (Header.Length == 0x00) return null;

                // проверить указание внутренних элементов
                if (Header.Length == 0x80) throw new InvalidOperationException(); 

                // создать список закодированных представлений
                List<byte[]> encodeds = new List<byte[]>(); 

                // для всех внутренних объектов
                foreach (ExtendedHeader child in Children)
                {
                    // извлечь закодированное представление
                    ASN1.IEncodable encodable = child.DecodeString(tagScheme, encoded, ref offset); 
                    
                    // добавить закодированное представление в список
                    if (encodable != null) encodeds.Add(encodable.Encoded); 
                }
                // объединить закодированные представления
                byte[] content = Arrays.Concat(encodeds.ToArray()); 

                // вернуть закодированное представление
                return ASN1.Encodable.Encode(Header.Tag.AsnTag, Header.Tag.PC, content); 
            }
        }
    }
}
