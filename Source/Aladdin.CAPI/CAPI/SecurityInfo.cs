using System; 

namespace Aladdin.CAPI
{
	///////////////////////////////////////////////////////////////////////////
	// Информация об защищенном объекте
	///////////////////////////////////////////////////////////////////////////
	public sealed class SecurityInfo : IEquatable<SecurityInfo>
	{
        // имя хранилища защищенных объектов и имя объекта
        public readonly Scope Scope; public readonly string Store; public readonly object Name;

        // получить информацию объекта
        public SecurityInfo(Scope scope, string fullName)
        {
            // найти последний разделитель
            Scope = scope; int index = fullName.LastIndexOf('\\'); 
            
            // извлечь имя хранилища
            Store = (index >= 0) ? fullName.Substring(0, index) : null; 

            // сохранить имя объекта
            Name = (index >= 0) ? fullName.Substring(index + 1) : fullName; 
        }
		// конструктор
		public SecurityInfo(Scope scope, string store, object name)
		{
			// сохранить переданные параметры
			Scope = scope; Store = store; Name = name; 
		}
        // полное имя контейнера
        public string FullName { get 
        { 
            // проверить наличие родительского хранилища
            if (Store == null) return Name.ToString(); 

            // указать отображаемое имя объекта
            string displayName = "<NONAME>"; if (Name is System.IO.MemoryStream)
            {
                // выполнить преобразование типа
                System.IO.MemoryStream stream = (System.IO.MemoryStream)Name;

                // закодировать содержимое буфера
                displayName = Convert.ToBase64String(stream.ToArray());
            }
            // указать отображаемое имя объекта
            else if (Name is String) displayName = Name.ToString(); 

            // вернуть полное имя объекта
            return String.Format("{0}\\{1}", Store, displayName); 
        }}
        // сравнить объекты
        public override bool Equals(object obj) { return Equals((SecurityInfo)obj); }
        // сравнить объекты
        public bool Equals(SecurityInfo obj)
        {
            // проверить наличие объекта
            if (obj == null) return false; if (obj == this) return true; 

            // сравнить имена объектов
            return (Name is String) && FullName == obj.FullName; 
        }
        // хэш-код объекта
        public override int GetHashCode() { return FullName.GetHashCode(); }
    }; 
}
