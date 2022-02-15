using System; 
using System.Windows.Forms;

namespace Aladdin.CAPI.GUI
{
	///////////////////////////////////////////////////////////////////////////
	// ������ ������ ����������������� ��������
	///////////////////////////////////////////////////////////////////////////
	public partial class CultureDialog : Form
	{
        // ������� ����������������� ��������
        public static PBE.PBECulture Show(IWin32Window parent, CultureControl[] controls)
        {
            // ������� ������
            CultureDialog dialog = new CultureDialog(controls); 

            // ���������� ������
            DialogResult result = Aladdin.GUI.ModalView.Show(parent, dialog); 

			// ��������� ��������� �������
			return (result == DialogResult.OK) ? dialog.Culture : null;
        }
		// �����������
		public CultureDialog(params CultureControl[] controls) 
        { 
            // ��������� ���������� ���������
            InitializeComponent(); 

			// ��� ���� ��������
			foreach (CultureControl control in controls)
			{
				// �������� �������� ��������
				tabControl.TabPages.Add(CreateTabPage(tabTemplate, control));
 			}
			// ������� ��������� ��������
			tabControl.TabPages.Remove(tabTemplate);

			// ��������� ������� �������� 
			if (tabControl.TabPages.Count == 0) throw new NotFoundException(); 
        }
		// �����������
		public CultureDialog() { InitializeComponent(); } 

        // ��������� ����������������� ��������
        public PBE.PBECulture Culture { get { return culture; } } private PBE.PBECulture culture;   

		///////////////////////////////////////////////////////////////////////
		// ������� 
		///////////////////////////////////////////////////////////////////////
		private void OnLoad(object sender, System.EventArgs e)
		{
		}
		private TabPage CreateTabPage(TabPage template, CultureControl control)
		{
			// ������� ��������� ��� ��������
			TabPage tabPage = new TabPage(); tabPage.Location = template.Location; 

			// ������� ��������� ���������� ��������
			tabPage.Padding = template.Padding; tabPage.Size = template.Size;	 

			// ������� �������� � �������������� 
			tabPage.Text = control.Type; tabPage.Controls.Add(control); return tabPage; 
		}
        private void OnSelect(object sender, EventArgs e)
        {
			// �������� �������� ��������
			TabPage tabPage = tabControl.TabPages[tabControl.SelectedIndex]; 

			// ������� ����������������� ��������
			culture = ((CultureControl)tabPage.Controls[0]).GetCulture(); 
        }
	}
}
