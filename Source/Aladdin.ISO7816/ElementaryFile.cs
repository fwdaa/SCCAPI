using System;
using System.IO;
using System.Collections.Generic;

namespace Aladdin.ISO7816
{
    ///////////////////////////////////////////////////////////////////////////////
    // Элементарный файл
    ///////////////////////////////////////////////////////////////////////////////
    public abstract class ElementaryFile : File
    {
        // конструктор
        internal ElementaryFile(DedicatedFile parent, ushort id)
         
            // сохранить переданные параметры
            : base(parent, id, new BER.FileControlInformation()) { this.shortID = null; }
        
        // конструктор
        internal ElementaryFile(DedicatedFile parent, byte shortID)
         
            // сохранить переданные параметры
            : base(parent, null, new BER.FileControlInformation()) { this.shortID = shortID; }
        
        // конструктор
        internal ElementaryFile(DedicatedFile parent, 
            ushort? id, byte? shortID, BER.FileControlInformation info) 
         
            // сохранить переданные параметры
            : base(parent, id, info) { this.shortID = shortID; }
        
        // сокращенный идентификатор файла
        public byte? ShortID { get { return shortID; }} private byte? shortID; 
    
        // выделить родительский каталог
        public override DedicatedFile SelectParent(LogicalChannel channel)
        {
            // определить структуру файла
            FileStructure fileStructure = FileStructure; 
        
            // для файла объектов
            if (fileStructure == ISO7816.FileStructure.Unknown              || 
                fileStructure == ISO7816.FileStructure.DataObject           ||
                fileStructure == ISO7816.FileStructure.DataObjectBERTLV     ||
                fileStructure == ISO7816.FileStructure.DataObjectSimpleTLV)
            {
                // выделить родительский каталог
                Parent.SelectFromChild(channel); 
            }
            return Parent; 
        }
        // общий размер байтов
        public int? ContentSize { get 
        {
            // найти объект
            DataObject[] objs = Info[Tag.Context(0x00, ASN1.PC.Primitive)]; if (objs.Length == 0) return null; 

            // проверить размер содержимого
            byte[] content = objs[0].Content; if (content.Length > 4) return Int32.MaxValue; 
        
            // для всех байтов размера
            int value = 0; foreach (byte next in content) value = (value << 8) | (next & 0xFF); 
        
            // вернуть размер файла
            return (value >= 0) ? value : Int32.MaxValue; 
        }}
        // прочитать содержимое файла
        public abstract Response ReadContent(LogicalChannel channel, 
            SecureType secureType, SecureClient secureClient
        ); 
    }
}
