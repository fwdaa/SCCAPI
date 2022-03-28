using System;
using System.IO;
using System.Reflection;
using System.Security;
using System.Security.Permissions;
using System.Runtime.Serialization;

namespace Aladdin.ASN1
{
	///////////////////////////////////////////////////////////////////////////
	// Объект с явным приведением типа от произвольного типа
	///////////////////////////////////////////////////////////////////////////
    [Serializable]
	public class Explicit : Encodable
	{
		// закодировать объект
		public static IEncodable Encode(Tag tag, IEncodable encodable)
		{
			// закодировать объект
			return Encodable.Encode(tag, PC.Constructed, encodable.Encoded); 
		}
		// конструктор при сериализации
        protected Explicit(SerializationInfo info, StreamingContext context) : base(info, context)
        {
			// получить конструктор при раскодировании
			ConstructorInfo constructor = GetType().GetConstructor(
				new Type[] { typeof(IEncodable) }
			); 
			// при отсутствии конструктора
			if (constructor != null)
			try {  
				// создать объект 
				Explicit instance = (Explicit)constructor.Invoke(new object[] { this }); 

				// сохранить переменные объекта
				value = instance.value; 
			}
			// обработать возможное исключение
			catch (TargetInvocationException e) { throw e.InnerException; }
		
			// прочитать представление
			else value = (IEncodable)info.GetValue("Inner", typeof(IEncodable)); 
        }
		// конструктор при раскодировании
		public Explicit(IObjectFactory factory, IEncodable encodable) : base(encodable) 
		{
			// проверить корректность способа кодирования
			if (encodable.PC != PC.Constructed) throw new InvalidDataException();

			// раскодировать внутренний объект
			value = factory.Decode(Encodable.Decode(encodable.Content)); 

			// проверить наличие только одного объекта
			if (value.Encoded.Length != encodable.Content.Length)
			{
				// при ошибке выбросить исключение
				throw new InvalidDataException();
			}
		}
		// конструктор при закодировании
		public Explicit(IObjectFactory factory, Tag tag, IEncodable value) : base(tag, PC.Constructed) 
		{
			// проверить корректность объекта
			this.value = factory.Decode(value); 
		} 
		// содержимое объекта
		protected override byte[] GetContent() { return value.Encoded; }

		// исходный объект
		public IEncodable Inner { get { return value; } } protected IEncodable value; 

        /////////////////////////////////////////////////////////////////////////////
        // Сохранение данных
        /////////////////////////////////////////////////////////////////////////////
        [SecurityCritical]
        [SecurityPermission(SecurityAction.LinkDemand, SerializationFormatter = true)]        
        public override void GetObjectData(SerializationInfo info, StreamingContext context)
        {
            // сохранить бинарное представление
            base.GetObjectData(info, context); 
			
			// получить конструктор при раскодировании
			ConstructorInfo constructor = GetType().GetConstructor(
				new Type[] { typeof(IEncodable) }
			); 
			// сохранить данные при отсутствии конструктора
			if (constructor == null) info.AddValue("Inner", value); 
        }
	}
	///////////////////////////////////////////////////////////////////////////
	// Объект с явным приведением типа от указанного типа
	///////////////////////////////////////////////////////////////////////////
    [Serializable]
	public sealed class Explicit<T> : Explicit where T : IEncodable
	{
		// конструктор при сериализации
        private Explicit(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public Explicit(IObjectFactory<T> factory, IEncodable encodable) : base(factory, encodable) 
		{
			// раскодировать внутренний объект
			value = factory.Decode(value); 
		}
		// конструктор при раскодировании
		public Explicit(IEncodable encodable) : this(new ObjectCreator<T>().Factory(), encodable) {}

		// конструктор при закодировании
		public Explicit(IObjectFactory<T> factory, Tag tag, T value) : base(factory, tag, value) {}

		// конструктор при закодировании
		public Explicit(Tag tag, T value) : this(new ObjectCreator<T>().Factory(), tag, value) {} 

		// исходный объект
		public new T Inner { get { return (T)base.Inner; } }
	}
}
