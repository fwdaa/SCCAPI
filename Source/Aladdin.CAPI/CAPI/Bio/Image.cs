using System;

namespace Aladdin.CAPI.Bio
{
	///////////////////////////////////////////////////////////////////////////
    /// Изображение отпечатка 
	///////////////////////////////////////////////////////////////////////////
    public abstract class Image 
    {
		// изображение отпечатка
        public abstract Object GetThumbnailImage(int thumbWidth, int thumbHeight); 
        
        // качество отпечатка
        public abstract int Quality { get; }
    }
}
