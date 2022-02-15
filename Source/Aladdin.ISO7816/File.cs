using System;
using System.IO;
using System.Collections.Generic;

namespace Aladdin.ISO7816
{
    ///////////////////////////////////////////////////////////////////////////////
    // Файл
    ///////////////////////////////////////////////////////////////////////////////
    public abstract class File 
    {
        // родительский каталог и шаблон описания файла
        private DedicatedFile parent; private BER.FileControlInformation info;
    
        // идентификатор, путь файла и способ кодирования данных
        private ushort? id; private ushort[] path; private DataCoding dataCoding;
    
        // конструктор
        protected File(ushort? id, DataCoding dataCoding, BER.FileControlInformation info) 
        { 
            // сохранить переданные параметры
            this.parent = null; this.info = info;

            // указать путь файла
            this.id = id; path = (id.HasValue) ? new ushort[] { id.Value } : null; 

            // сохранить способ кодирования данных
            this.dataCoding = this.info.GetDataCoding(dataCoding); 
        }
        // конструктор
        protected File(DedicatedFile parent, ushort? id, BER.FileControlInformation info) 
        { 
            // сохранить переданные параметры
            this.parent = parent; this.info = info;

            // проверить наличие пути
            this.id = id; if (!id.HasValue || parent.Path == null) path = null; 
        
            // получить путь родительского каталога
            else { ushort[] parentPath = parent.Path; 
            
                // указать идентификатор файла
                path = new ushort[parentPath.Length + 1]; path[parentPath.Length] = id.Value;
            
                // скопировать родительский путь
                Array.Copy(parentPath, 0, path, 0, path.Length - 1);
            }
            // сохранить способ кодирования данных
            this.dataCoding = this.info.GetDataCoding(parent.DataCoding); 
        }
        // каталог файла
        public DedicatedFile Parent { get { return parent; }}
    
        // идентификатор файла
        public ushort? ID { get { return id; }}
        // путь файла
        public ushort[] Path { get { return path; }}
    
        // информация файла
        public BER.FileControlInformation Info { get { return info; }}
        // способ кодирования данных
        public DataCoding DataCoding { get { return dataCoding; }}
    
        // категория файла
        public virtual int FileCategory { get { return ISO7816.FileCategory.Unknown; }}
        // структура файла
        public virtual FileStructure FileStructure { get { return ISO7816.FileStructure.Unknown; }}

        // выделить родительский каталог
        public abstract DedicatedFile SelectParent(LogicalChannel channel); 
    }
}
