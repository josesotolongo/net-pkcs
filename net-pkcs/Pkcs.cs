using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace net_pkcs
{
    public class Pkcs
    {
        private const string FILE_PATH = @"C:\Users\jys1021\source\repos\net-pkcs\net-pkcs\dll\eToken.dll";

        private Pkcs11InteropFactories _factory;

        public Pkcs()
        {
            _factory = new Pkcs11InteropFactories();
        }

        public void StartupExample()
        {
            Pkcs11InteropFactories factories = new Pkcs11InteropFactories();

            using (IPkcs11Library pkcs11Library = _factory.Pkcs11LibraryFactory.LoadPkcs11Library(factories, FILE_PATH, AppType.MultiThreaded))
            {
                ILibraryInfo libInfo = pkcs11Library.GetInfo();

                Console.WriteLine("Library");
                Console.WriteLine("  Manufacturer:       " + libInfo.ManufacturerId);
                Console.WriteLine("  Description:        " + libInfo.LibraryDescription);
                Console.WriteLine("  Version:            " + libInfo.LibraryVersion);

                foreach (ISlot slot in pkcs11Library.GetSlotList(SlotsType.WithOrWithoutTokenPresent))
                {
                    ISlotInfo slotInfo = slot.GetSlotInfo();

                    Console.WriteLine();
                    Console.WriteLine("Slot");
                    Console.WriteLine("  Manufacturer:       " + slotInfo.ManufacturerId);
                    Console.WriteLine("  Description:        " + slotInfo.SlotDescription);
                    Console.WriteLine("  Token present:      " + slotInfo.SlotFlags.TokenPresent);

                    if (slotInfo.SlotFlags.TokenPresent)
                    {
                        ITokenInfo tokenInfo = slot.GetTokenInfo();

                        Console.WriteLine("Token");
                        Console.WriteLine("  Manufacturer:       " + tokenInfo.ManufacturerId);
                        Console.WriteLine("  Model:              " + tokenInfo.Model);
                        Console.WriteLine("  Serial number:      " + tokenInfo.SerialNumber);
                        Console.WriteLine("  Label:              " + tokenInfo.Label);

                        Console.WriteLine("Supported Mechanisms: ");
                        foreach (CKM mech in slot.GetMechanismList())
                            Console.WriteLine(" " + mech);
                    }
                }
            }
        }

        public void GenerateKP()
        {
            using (IPkcs11Library pkcs11lib = _factory.Pkcs11LibraryFactory.LoadPkcs11Library(_factory, FILE_PATH, AppType.MultiThreaded))
            {
                ISlot slot = GetUsableSlot(pkcs11lib);

                using(ISession session = slot.OpenSession(SessionType.ReadWrite))
                {
                    session.Login(CKU.CKU_USER, "password123!");

                    byte[] ckaId = { 1 };

                    List<IObjectAttribute> publicKeyAttrib = new List<IObjectAttribute>();
                    List<IObjectAttribute> privateKeyAttrib = new List<IObjectAttribute>();


                    
                    privateKeyAttrib.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY));
                    privateKeyAttrib.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, CKK.CKK_EC));

                    IMechanism mechanism = session.Factories.MechanismFactory.Create(CKM.CKM_EC_KEY_PAIR_GEN);

                    IObjectHandle pubKeyHandle = null;
                    IObjectHandle privateHandle = null;
                    session.GenerateKeyPair(mechanism, publicKeyAttrib, privateKeyAttrib, out pubKeyHandle, out privateHandle);
                }
            }
        }

        public void FindKey()
        {
            using (IPkcs11Library pkcs11lib = _factory.Pkcs11LibraryFactory.LoadPkcs11Library(_factory, FILE_PATH, AppType.MultiThreaded))
            {
                ISlot slot = GetUsableSlot(pkcs11lib);

                using (ISession session = slot.OpenSession(SessionType.ReadWrite))
                {
                    session.Login(CKU.CKU_USER, "password123!");

                    List<IObjectAttribute> objectAttributes = new List<IObjectAttribute>();
                    objectAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY));
                    objectAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, CKK.CKK_DES3));

                    session.FindObjectsInit(objectAttributes);

                    List<IObjectHandle> foundObj = session.FindObjects(2);
                }
            }
        }

        private ISlot GetUsableSlot(IPkcs11Library pkcslib)
        {
            List<ISlot> slots = pkcslib.GetSlotList(SlotsType.WithTokenPresent);
            ISlot matchingSlot = slots[0];
            
            return matchingSlot;
        }
    }
}
