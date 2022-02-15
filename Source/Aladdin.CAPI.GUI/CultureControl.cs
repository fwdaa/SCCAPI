using System; 
using System.Windows.Forms;

namespace Aladdin.CAPI.GUI
{
	///////////////////////////////////////////////////////////////////////////
	// Графический элемент выбора криптографической культуры
	///////////////////////////////////////////////////////////////////////////
	public class CultureControl : UserControl	
	{
        // тип семейства криптографических культур
        public virtual string Type { get { return String.Empty; }} 

		// получить криптографическую культуру
        public virtual PBE.PBECulture GetCulture() { return null; } 
	}
}
