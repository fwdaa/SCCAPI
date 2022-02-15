using System;
using System.Collections;
using System.Collections.Generic;

namespace Aladdin.ASN1
{
	/////////////////////////////////////////////////////////////////////////////
	// Типизированный перечислитель объектов
	/////////////////////////////////////////////////////////////////////////////
	internal class Enumerator<T> : IEnumerator<T>
	{
		// конструктор
		public Enumerator(IEnumerator enumerator)
			
			// сохранить переданные параметры
			{ this.enumerator = enumerator; } private IEnumerator enumerator;

		// получить текущий элемент
		public T Current { get { return (T)enumerator.Current; } }

		// получить текущий элемент
		object	IEnumerator.Current	{ get { return enumerator.Current;  } }

		// перейти на следующий элемент
		bool IEnumerator.MoveNext() { return enumerator.MoveNext(); }
  
		// сбросить состояние перечислителя
		void IEnumerator.Reset() { enumerator.Reset(); }
 
		// закрыть перечислитель
		void IDisposable.Dispose() {}
	}
}
