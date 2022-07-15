using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using System;
using System.IO;

namespace net_pkcs
{
    public class Program
    {
        
        static void Main(string[] args)
        {
            Pkcs pkcs = new Pkcs();

            //pkcs.GenerateKey();
            //pkcs.GenerateKP();
            pkcs.FindKey();
        }
    }
}
