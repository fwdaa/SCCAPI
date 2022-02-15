<Global.Microsoft.VisualBasic.CompilerServices.DesignerGenerated()> _
Partial Class Form1
    Inherits System.Windows.Forms.Form

    'Form overrides dispose to clean up the component list.
    <System.Diagnostics.DebuggerNonUserCode()> _
    Protected Overrides Sub Dispose(ByVal disposing As Boolean)
        Try
            If disposing AndAlso components IsNot Nothing Then
                components.Dispose()
            End If
        Finally
            MyBase.Dispose(disposing)
        End Try
    End Sub

    'Required by the Windows Form Designer
    Private components As System.ComponentModel.IContainer

    'NOTE: The following procedure is required by the Windows Form Designer
    'It can be modified using the Windows Form Designer.  
    'Do not modify it using the code editor.
    <System.Diagnostics.DebuggerStepThrough()> _
    Private Sub InitializeComponent()
        Me.templateBox = New System.Windows.Forms.TextBox
        Me.QualityBox = New System.Windows.Forms.TextBox
        Me.Label1 = New System.Windows.Forms.Label
        Me.ImageBox1 = New System.Windows.Forms.PictureBox
        Me.Button1 = New System.Windows.Forms.Button
        Me.Button2 = New System.Windows.Forms.Button
        Me.Button3 = New System.Windows.Forms.Button
        Me.VerifyButton = New System.Windows.Forms.Button
        Me.EnrollButton = New System.Windows.Forms.Button
        Me.TextBox1 = New System.Windows.Forms.TextBox
        Me.TextBox2 = New System.Windows.Forms.TextBox
        Me.Button4 = New System.Windows.Forms.Button
        Me.Button5 = New System.Windows.Forms.Button
        Me.ListBox1 = New System.Windows.Forms.ListBox
        Me.QualityBox2 = New System.Windows.Forms.TextBox
        Me.Label2 = New System.Windows.Forms.Label
        Me.PictureBox1 = New System.Windows.Forms.PictureBox
        Me.TextBox4 = New System.Windows.Forms.TextBox
        Me.TextBox5 = New System.Windows.Forms.TextBox
        Me.PictureBox2 = New System.Windows.Forms.PictureBox
        Me.TextBox6 = New System.Windows.Forms.TextBox
        CType(Me.ImageBox1, System.ComponentModel.ISupportInitialize).BeginInit()
        CType(Me.PictureBox1, System.ComponentModel.ISupportInitialize).BeginInit()
        CType(Me.PictureBox2, System.ComponentModel.ISupportInitialize).BeginInit()
        Me.SuspendLayout()
        '
        'templateBox
        '
        Me.templateBox.BackColor = System.Drawing.SystemColors.Window
        Me.templateBox.Font = New System.Drawing.Font("Courier New", 8.25!, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, CType(0, Byte))
        Me.templateBox.Location = New System.Drawing.Point(290, 12)
        Me.templateBox.Multiline = True
        Me.templateBox.Name = "templateBox"
        Me.templateBox.ReadOnly = True
        Me.templateBox.ScrollBars = System.Windows.Forms.ScrollBars.Vertical
        Me.templateBox.Size = New System.Drawing.Size(128, 186)
        Me.templateBox.TabIndex = 3
        '
        'QualityBox
        '
        Me.QualityBox.BackColor = System.Drawing.SystemColors.Window
        Me.QualityBox.Location = New System.Drawing.Point(196, 168)
        Me.QualityBox.Name = "QualityBox"
        Me.QualityBox.ReadOnly = True
        Me.QualityBox.Size = New System.Drawing.Size(88, 20)
        Me.QualityBox.TabIndex = 9
        '
        'Label1
        '
        Me.Label1.AutoSize = True
        Me.Label1.Location = New System.Drawing.Point(146, 170)
        Me.Label1.Name = "Label1"
        Me.Label1.Size = New System.Drawing.Size(42, 13)
        Me.Label1.TabIndex = 8
        Me.Label1.Text = "Quality:"
        '
        'ImageBox1
        '
        Me.ImageBox1.BorderStyle = System.Windows.Forms.BorderStyle.FixedSingle
        Me.ImageBox1.Location = New System.Drawing.Point(146, 12)
        Me.ImageBox1.Name = "ImageBox1"
        Me.ImageBox1.Size = New System.Drawing.Size(138, 144)
        Me.ImageBox1.TabIndex = 6
        Me.ImageBox1.TabStop = False
        '
        'Button1
        '
        Me.Button1.Location = New System.Drawing.Point(12, 204)
        Me.Button1.Name = "Button1"
        Me.Button1.Size = New System.Drawing.Size(128, 20)
        Me.Button1.TabIndex = 10
        Me.Button1.Text = "1 - ListReaders"
        Me.Button1.UseVisualStyleBackColor = True
        '
        'Button2
        '
        Me.Button2.Location = New System.Drawing.Point(146, 204)
        Me.Button2.Name = "Button2"
        Me.Button2.Size = New System.Drawing.Size(138, 20)
        Me.Button2.TabIndex = 11
        Me.Button2.Text = "2 - CaptureImage"
        Me.Button2.UseVisualStyleBackColor = True
        '
        'Button3
        '
        Me.Button3.Location = New System.Drawing.Point(290, 204)
        Me.Button3.Name = "Button3"
        Me.Button3.Size = New System.Drawing.Size(128, 20)
        Me.Button3.TabIndex = 12
        Me.Button3.Text = "3 - Create Template"
        Me.Button3.UseVisualStyleBackColor = True
        '
        'VerifyButton
        '
        Me.VerifyButton.Location = New System.Drawing.Point(836, 202)
        Me.VerifyButton.Name = "VerifyButton"
        Me.VerifyButton.Size = New System.Drawing.Size(138, 20)
        Me.VerifyButton.TabIndex = 14
        Me.VerifyButton.Text = "7 - Match on Card"
        Me.VerifyButton.UseVisualStyleBackColor = True
        '
        'EnrollButton
        '
        Me.EnrollButton.Location = New System.Drawing.Point(702, 204)
        Me.EnrollButton.Name = "EnrollButton"
        Me.EnrollButton.Size = New System.Drawing.Size(128, 20)
        Me.EnrollButton.TabIndex = 13
        Me.EnrollButton.Text = "6 - Store on SC"
        Me.EnrollButton.UseVisualStyleBackColor = True
        '
        'TextBox1
        '
        Me.TextBox1.Location = New System.Drawing.Point(12, 230)
        Me.TextBox1.Name = "TextBox1"
        Me.TextBox1.Size = New System.Drawing.Size(962, 20)
        Me.TextBox1.TabIndex = 15
        Me.TextBox1.Text = "Click ListReaders to list connected supported biometric readers."
        '
        'TextBox2
        '
        Me.TextBox2.Location = New System.Drawing.Point(12, 256)
        Me.TextBox2.Name = "TextBox2"
        Me.TextBox2.Size = New System.Drawing.Size(962, 20)
        Me.TextBox2.TabIndex = 16
        '
        'Button4
        '
        Me.Button4.Location = New System.Drawing.Point(424, 204)
        Me.Button4.Name = "Button4"
        Me.Button4.Size = New System.Drawing.Size(138, 20)
        Me.Button4.TabIndex = 17
        Me.Button4.Text = "4 - CaptureValidate Image"
        Me.Button4.UseVisualStyleBackColor = True
        '
        'Button5
        '
        Me.Button5.Location = New System.Drawing.Point(568, 204)
        Me.Button5.Name = "Button5"
        Me.Button5.Size = New System.Drawing.Size(128, 20)
        Me.Button5.TabIndex = 18
        Me.Button5.Text = "5 - Validate template"
        Me.Button5.UseVisualStyleBackColor = True
        '
        'ListBox1
        '
        Me.ListBox1.FormattingEnabled = True
        Me.ListBox1.HorizontalScrollbar = True
        Me.ListBox1.Location = New System.Drawing.Point(12, 12)
        Me.ListBox1.Name = "ListBox1"
        Me.ListBox1.Size = New System.Drawing.Size(128, 186)
        Me.ListBox1.TabIndex = 19
        '
        'QualityBox2
        '
        Me.QualityBox2.BackColor = System.Drawing.SystemColors.Window
        Me.QualityBox2.Location = New System.Drawing.Point(474, 170)
        Me.QualityBox2.Name = "QualityBox2"
        Me.QualityBox2.ReadOnly = True
        Me.QualityBox2.Size = New System.Drawing.Size(88, 20)
        Me.QualityBox2.TabIndex = 22
        '
        'Label2
        '
        Me.Label2.AutoSize = True
        Me.Label2.Location = New System.Drawing.Point(424, 172)
        Me.Label2.Name = "Label2"
        Me.Label2.Size = New System.Drawing.Size(42, 13)
        Me.Label2.TabIndex = 21
        Me.Label2.Text = "Quality:"
        '
        'PictureBox1
        '
        Me.PictureBox1.BorderStyle = System.Windows.Forms.BorderStyle.FixedSingle
        Me.PictureBox1.Location = New System.Drawing.Point(424, 12)
        Me.PictureBox1.Name = "PictureBox1"
        Me.PictureBox1.Size = New System.Drawing.Size(138, 144)
        Me.PictureBox1.TabIndex = 20
        Me.PictureBox1.TabStop = False
        '
        'TextBox4
        '
        Me.TextBox4.BackColor = System.Drawing.SystemColors.Window
        Me.TextBox4.Location = New System.Drawing.Point(568, 12)
        Me.TextBox4.Multiline = True
        Me.TextBox4.Name = "TextBox4"
        Me.TextBox4.ReadOnly = True
        Me.TextBox4.ScrollBars = System.Windows.Forms.ScrollBars.Vertical
        Me.TextBox4.Size = New System.Drawing.Size(128, 186)
        Me.TextBox4.TabIndex = 23
        '
        'TextBox5
        '
        Me.TextBox5.BackColor = System.Drawing.SystemColors.Window
        Me.TextBox5.Location = New System.Drawing.Point(702, 12)
        Me.TextBox5.Multiline = True
        Me.TextBox5.Name = "TextBox5"
        Me.TextBox5.ReadOnly = True
        Me.TextBox5.ScrollBars = System.Windows.Forms.ScrollBars.Vertical
        Me.TextBox5.Size = New System.Drawing.Size(128, 186)
        Me.TextBox5.TabIndex = 24
        '
        'PictureBox2
        '
        Me.PictureBox2.BorderStyle = System.Windows.Forms.BorderStyle.FixedSingle
        Me.PictureBox2.Location = New System.Drawing.Point(836, 12)
        Me.PictureBox2.Name = "PictureBox2"
        Me.PictureBox2.Size = New System.Drawing.Size(138, 144)
        Me.PictureBox2.TabIndex = 25
        Me.PictureBox2.TabStop = False
        '
        'TextBox6
        '
        Me.TextBox6.BackColor = System.Drawing.SystemColors.Window
        Me.TextBox6.Location = New System.Drawing.Point(836, 162)
        Me.TextBox6.Multiline = True
        Me.TextBox6.Name = "TextBox6"
        Me.TextBox6.ReadOnly = True
        Me.TextBox6.Size = New System.Drawing.Size(138, 34)
        Me.TextBox6.TabIndex = 26
        '
        'Form1
        '
        Me.AutoScaleDimensions = New System.Drawing.SizeF(6.0!, 13.0!)
        Me.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font
        Me.ClientSize = New System.Drawing.Size(980, 285)
        Me.Controls.Add(Me.TextBox6)
        Me.Controls.Add(Me.PictureBox2)
        Me.Controls.Add(Me.TextBox5)
        Me.Controls.Add(Me.TextBox4)
        Me.Controls.Add(Me.QualityBox2)
        Me.Controls.Add(Me.Label2)
        Me.Controls.Add(Me.PictureBox1)
        Me.Controls.Add(Me.ListBox1)
        Me.Controls.Add(Me.Button5)
        Me.Controls.Add(Me.Button4)
        Me.Controls.Add(Me.TextBox2)
        Me.Controls.Add(Me.TextBox1)
        Me.Controls.Add(Me.VerifyButton)
        Me.Controls.Add(Me.EnrollButton)
        Me.Controls.Add(Me.Button3)
        Me.Controls.Add(Me.Button2)
        Me.Controls.Add(Me.Button1)
        Me.Controls.Add(Me.QualityBox)
        Me.Controls.Add(Me.Label1)
        Me.Controls.Add(Me.ImageBox1)
        Me.Controls.Add(Me.templateBox)
        Me.Name = "Form1"
        Me.StartPosition = System.Windows.Forms.FormStartPosition.CenterScreen
        Me.Text = "VB Example 1 - BioMatch Flex H"
        CType(Me.ImageBox1, System.ComponentModel.ISupportInitialize).EndInit()
        CType(Me.PictureBox1, System.ComponentModel.ISupportInitialize).EndInit()
        CType(Me.PictureBox2, System.ComponentModel.ISupportInitialize).EndInit()
        Me.ResumeLayout(False)
        Me.PerformLayout()

    End Sub
    Friend WithEvents templateBox As System.Windows.Forms.TextBox
    Friend WithEvents QualityBox As System.Windows.Forms.TextBox
    Friend WithEvents Label1 As System.Windows.Forms.Label
    Friend WithEvents ImageBox1 As System.Windows.Forms.PictureBox
    Friend WithEvents Button1 As System.Windows.Forms.Button
    Friend WithEvents Button2 As System.Windows.Forms.Button
    Friend WithEvents Button3 As System.Windows.Forms.Button
    Friend WithEvents VerifyButton As System.Windows.Forms.Button
    Friend WithEvents EnrollButton As System.Windows.Forms.Button
    Friend WithEvents TextBox1 As System.Windows.Forms.TextBox
    Friend WithEvents TextBox2 As System.Windows.Forms.TextBox
    Friend WithEvents Button4 As System.Windows.Forms.Button
    Friend WithEvents Button5 As System.Windows.Forms.Button
    Friend WithEvents ListBox1 As System.Windows.Forms.ListBox
    Friend WithEvents QualityBox2 As System.Windows.Forms.TextBox
    Friend WithEvents Label2 As System.Windows.Forms.Label
    Friend WithEvents PictureBox1 As System.Windows.Forms.PictureBox
    Friend WithEvents TextBox4 As System.Windows.Forms.TextBox
    Friend WithEvents TextBox5 As System.Windows.Forms.TextBox
    Friend WithEvents PictureBox2 As System.Windows.Forms.PictureBox
    Friend WithEvents TextBox6 As System.Windows.Forms.TextBox

End Class
