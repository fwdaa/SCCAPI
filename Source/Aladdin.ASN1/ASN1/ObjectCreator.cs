using System;
using System.Reflection;

namespace Aladdin.ASN1
{
	///////////////////////////////////////////////////////////////////////////
	// Фабрика создания фабрик объектов
	///////////////////////////////////////////////////////////////////////////
	public class ObjectCreator<T> where T : IEncodable
	{
		// экземпляр фабрики
		public IObjectFactory<T> Factory(params object[] args) 
		{ 
			// экземпляр фабрики
			return new ObjectFactory<T>(args); 
		}  
 	}
}
