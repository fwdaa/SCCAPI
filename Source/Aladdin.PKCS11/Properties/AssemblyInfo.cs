using System.Security;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Diagnostics.CodeAnalysis;

//
// General Information about an assembly is controlled through the following 
// set of attributes. Change these attribute values to modify the information
// associated with an assembly.
//
[assembly: AssemblyTitle("Aladdin.PKCS11")]
[assembly: AssemblyDescription("")]
[assembly: AssemblyConfiguration("")]
[assembly: AssemblyCompany("Aladdin R.D.")]
[assembly: AssemblyProduct("Aladdin.CAPI")]
[assembly: AssemblyCopyright("Copyright © Aladdin R.D. 2021")]
[assembly: AssemblyTrademark("")]
[assembly: AssemblyCulture("")]

// Setting ComVisible to false makes the types in this assembly not visible 
// to COM components.  If you need to access a type in this assembly from 
// COM, set the ComVisible attribute to true on that type.
[assembly: ComVisible(false)]

//
// Version information for an assembly consists of the following four values:
//
//      Major Version
//      Minor Version 
//      Build Number
//      Revision
//
// You can specify all the values or you can default the Revision and Build Numbers 
// by using the '*' as shown below:

[assembly: AssemblyVersion("8.0.0.140")]
[assembly: AssemblyFileVersion("8.0.0.140")]
[assembly: AllowPartiallyTrustedCallers]

[assembly: SuppressMessage("Microsoft.Security", "CA2111:PointersShouldNotBeVisible",  
    Scope = "module", Target = "Aladdin.PKCS11", Justification = ""
)]
