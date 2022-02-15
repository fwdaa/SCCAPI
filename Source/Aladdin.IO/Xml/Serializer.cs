using System;
using System.IO;
using System.Text;
using System.Xml;
using System.Xml.Serialization;

namespace Aladdin.IO.Xml
{
    ///////////////////////////////////////////////////////////////////////////
    // Запись/чтение данных в формате XML
    ///////////////////////////////////////////////////////////////////////////
    public class Serializer : ObjectSerializer
    {
        // способ записи объектов
        private XmlSerializer serializer; 
        
        // кодировка символов и корневые пространства имен
        private Encoding encoding; private XmlSerializerNamespaces namespaces; 

        // параметры чтения и записи
        private XmlReaderSettings readSettings; private XmlWriterSettings writeSettings; 

        // конструктор
        public Serializer(Type type, Encoding encoding, XmlSerializerNamespaces namespaces, 
            XmlReaderSettings readSettings, XmlWriterSettings writeSettings)
        {
            // указать способ записи объектов
            serializer = new XmlSerializer(type); 

            // сохранить переданные параметры
            this.encoding = encoding; this.namespaces = namespaces; 

            // сохранить переданные параметры
            this.readSettings = readSettings; this.writeSettings = writeSettings; 
        }
        // конструктор
        public Serializer(Type type, Encoding encoding, 
            XmlSerializerNamespaces namespaces, XmlReaderSettings readSettings) 

            // сохранить переданные параметры
            : this(type, encoding, namespaces, readSettings, new XmlWriterSettings()) { }

        // конструктор
        public Serializer(Type type, Encoding encoding, 
            XmlSerializerNamespaces namespaces, XmlWriterSettings writeSettings) 
            
            // сохранить переданные параметры
            : this(type, encoding, namespaces, new XmlReaderSettings(), writeSettings) { }

        // конструктор
        public Serializer(Type type, Encoding encoding, XmlSerializerNamespaces namespaces)

            // сохранить переданные параметры
            : this(type, encoding, namespaces, new XmlReaderSettings(), new XmlWriterSettings()) { }

        // прочитать объект из потока
        public override object Read(Stream stream)
        {
            // указать используемую кодировку
            using (StreamReader textReader = new StreamReader(stream, encoding))
            {
                // указать считыватель XML
                XmlReader reader = XmlReader.Create(textReader, readSettings); 
                
                // прочитать объект
                return serializer.Deserialize(reader);
                
            }
        }
        // записать объект в поток
        public override void Write(object obj, Stream stream)
        {
            // указать используемую кодировку
            using (StreamWriter textWriter = new StreamWriter(stream, encoding))
            {
                // указать считыватель XML
                XmlWriter writer = XmlWriter.Create(textWriter, writeSettings); 
                
                // записать объект по умолчанию
                if (namespaces == null) serializer.Serialize(writer, obj);

                // записать объект с пространствами имен
                else serializer.Serialize(writer, obj, namespaces); 
            }
        }
    }
}
