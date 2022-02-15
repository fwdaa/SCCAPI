using System;

namespace Aladdin.CAPI.SCard
{
    ///////////////////////////////////////////////////////////////////////////
    // Апплет на смарт-карте
    ///////////////////////////////////////////////////////////////////////////
    public abstract class Applet : SecurityObject
    {
        // конструктор
        protected Applet(Card store, string name) : base(store) { this.name = name; }

        // используемая смарт-карта
        public PCSC.Card Card { get { return ((Card)Store).PCSCCard; }}

        // сеанс взаимодействия с апплетом
        public abstract PCSC.ReaderSession Session { get; }

        // имя апплета
        public override object Name { get { return name; }} private string name; 

        // серийный номер апплета
        public abstract byte[] GetSerial(); 

        ///////////////////////////////////////////////////////////////////////
        // Общая информация 
        ///////////////////////////////////////////////////////////////////////

        // метка смарт-карты
        public abstract string GetLabel(); public abstract void SetLabel(string value); 

        // свободная память и общий объем памяти
        public abstract UInt32 FreeMemory(); public abstract UInt32 TotalMemory();

        // версии и идентификаторы апплета
        public abstract string GetHardwareVersion(); public abstract byte[] GetHardwareID(); 
        public abstract string GetSoftwareVersion(); public abstract byte[] GetSoftwareID(); 

        ///////////////////////////////////////////////////////////////////////
        // Файловая система 
        ///////////////////////////////////////////////////////////////////////

        // перечислить каталоги
        public virtual UInt16[] EnumerateFolders(params UInt16[] folder)
        {
            // перечислить каталоги
            return OpenFolder(folder).EnumerateFolders(); 
        }
        // перечислить файлы
        public virtual UInt16[] EnumerateFiles(params UInt16[] folder)
        {
            // перечислить файлы
            return OpenFolder(folder).EnumerateFiles(); 
        }
        // создать каталог
        public virtual IAppletFileFolder CreateFolder(UInt16[] path, FileObjectInfo info)
        {
            // выделить память для пути к каталогу
            UInt16[] folderPath = new UInt16[path.Length - 1];             

            // скопировать путь к каталогу
            Array.Copy(path, 0, folderPath, 0, folderPath.Length); 

            // создать каталог
            return OpenFolder(folderPath).CreateFolder(path[path.Length - 1], info); 
        }
        // создать файл
        public virtual IAppletFile CreateFile(UInt16[] path, FileObjectInfo info)
        {
            // выделить память для пути к каталогу
            UInt16[] folderPath = new UInt16[path.Length - 1];             

            // скопировать путь к каталогу
            Array.Copy(path, 0, folderPath, 0, folderPath.Length); 

            // создать файл
            return OpenFolder(folderPath).CreateFile(path[path.Length - 1], info); 
        }
        // открыть объект файловой системы
        public abstract IAppletFileFolder OpenFolder(params UInt16[] path); 
        public abstract IAppletFile       OpenFile  (params UInt16[] path);

        // удалить объект файловой системы
		public abstract void RemoveFolder(params UInt16[] path); 
        public abstract void RemoveFile  (params UInt16[] path);

        ///////////////////////////////////////////////////////////////////////
        // Форматирование апплета 
        ///////////////////////////////////////////////////////////////////////

        // параметры форматирования по умолчанию
        public abstract FormatParameters GetDefaultFormatParameters();

        // выполнить форматирование апплета
        public abstract void Format(String adminPIN, FormatParameters parameters); 
    }
}
