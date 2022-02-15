using System; 
using System.Collections.Generic; 

namespace Aladdin.CAPI
{
	///////////////////////////////////////////////////////////////////////////
	// Хранилище контейнеров
	///////////////////////////////////////////////////////////////////////////
    public abstract class ContainerStore : SecurityStore
    {
        // конструктор
		public ContainerStore(IProvider provider, Scope scope) : base(provider, scope) {}
        // конструктор
		public ContainerStore(SecurityStore parent) : base(parent) {}

        // используемый провайдер
        public new CryptoProvider Provider { get { return (CryptoProvider)base.Provider; }}

		///////////////////////////////////////////////////////////////////////
        // Иерархическое перечисление объектов
		///////////////////////////////////////////////////////////////////////
        public override string[] ParseObjectName(string fullName)
        {
            // вернуть разобранное имя
            return new string[] { fullName }; 
        }
		public override SecurityInfo[] EnumerateAllObjects()
        {
            // создать список описаний объектов
            List<SecurityInfo> infos = new List<SecurityInfo>(); 

            // для всех объектов
            foreach (string name in EnumerateObjects())
            {
                // добавить описание объекта
                infos.Add(new SecurityInfo(Scope, FullName, name)); 
            }
            return infos.ToArray(); 
        }
    }
}
