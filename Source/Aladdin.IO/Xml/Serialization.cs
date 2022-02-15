using System;
using System.Xml;
using System.Xml.Serialization;
using System.Text;

namespace Aladdin.IO.Xml
{
    ///////////////////////////////////////////////////////////////////////////
    // Создание способов записи/чтения данных
    ///////////////////////////////////////////////////////////////////////////
    public class Serialization : IO.Serialization
    {
        // кодировка символов и корневые пространства имен
        private Encoding encoding; private XmlSerializerNamespaces namespaces; 

        // параметры чтения и записи
        private XmlReaderSettings readSettings; private XmlWriterSettings writeSettings;

        // конструктор
        public Serialization(Encoding encoding, XmlSerializerNamespaces namespaces, 
            XmlReaderSettings readSettings, XmlWriterSettings writeSettings)
        {
            // сохранить переданные параметры
            this.encoding = encoding; this.namespaces = namespaces; 

            // сохранить переданные параметры
            this.readSettings = readSettings; this.writeSettings = writeSettings; 
        }
        // конструктор
        public Serialization(Encoding encoding, 
            XmlSerializerNamespaces namespaces, XmlReaderSettings readSettings) 

            // сохранить переданные параметры
            : this(encoding, namespaces, readSettings, new XmlWriterSettings()) { }

        // конструктор
        public Serialization(Encoding encoding, 
            XmlSerializerNamespaces namespaces, XmlWriterSettings writeSettings) 
            
            // сохранить переданные параметры
            : this(encoding, namespaces, new XmlReaderSettings(), writeSettings) { }

        // конструктор
        public Serialization(Encoding encoding, XmlSerializerNamespaces namespaces)

            // сохранить переданные параметры
            : this(encoding, namespaces, new XmlReaderSettings(), new XmlWriterSettings()) { }

        // создать способ записи/чтения данных
        public override IO.Serializer GetSerializer(Type type)
        {
            // создать способ записи/чтения данных
            return new Serializer(type, encoding, namespaces, readSettings, writeSettings); 
        }
    }
}
