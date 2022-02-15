using System;

namespace Aladdin.CAPI.Bio
{
	///////////////////////////////////////////////////////////////////////////
	// Провайдер биометрии
	///////////////////////////////////////////////////////////////////////////
    public abstract class Provider : RefObject
    {
		// имя провайдера 
        public abstract string Name { get; } 
        
        // перечислить биометрические считыватели 
        public abstract string[] EnumerateReaders();

        // получить объект считывателя
        public abstract Reader OpenReader(string name); 
        
		// создать шаблон отпечатка для сравнения
        public abstract MatchTemplate CreateMatchTemplate(
            Finger finger, Image image, object publicData
        );
        // cоздать шаблон отпечатка для регистрации 
        public abstract EnrollTemplate CreateEnrollTemplate(
            Finger finger, Image image, int far
        );
    }
}
