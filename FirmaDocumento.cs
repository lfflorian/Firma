using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using FirmaXadesNet;
using FirmaXadesNet.Clients;
using FirmaXadesNet.Crypto;
using FirmaXadesNet.Signature;
using FirmaXadesNet.Signature.Parameters;
using FirmaXadesNet.Upgraders;
using FirmaXadesNet.Upgraders.Parameters;
using FirmaXadesNet.Utils;
using System.Security.Cryptography.Xml;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using Microsoft.Xades;
using System.Xml.Linq;

namespace Firma
{
    public class FirmaDocumento
    {

        XadesService servicioXades = new XadesService();

        public XmlDocument FirmarDocumento(string rutaCertificado, string contraseñaCertificado, string rutaDocumento, string ubicacionDestino)
        {
            X509Certificate2 cert = new X509Certificate2(rutaCertificado, contraseñaCertificado, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);
            XadesService xadesService = new XadesService();

            SignatureParameters parametros = ParametrosdeFirma();

            var nombredocumento = Path.GetFileNameWithoutExtension(rutaDocumento);

            using (parametros.Signer = new Signer(cert))
            {
                var documento = FirmaXades(parametros, rutaDocumento);
                AlmacenamientoDocumento(documento, ubicacionDestino, nombredocumento);
                return documento.Document;
            }
        }

        public XmlDocument FirmarDocumento(string rutaCertificado, string contraseñaCertificado, string rutaDocumento)
        {
            X509Certificate2 cert = new X509Certificate2(rutaCertificado, contraseñaCertificado, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);

            SignatureParameters parametros = ParametrosdeFirma();
            
            using (parametros.Signer = new Signer(cert))
            {
                return FirmaXades(parametros, rutaDocumento).Document;
            }
        }

        private SignatureDocument FirmaXades(SignatureParameters sp, string ruta)
        {
            XadesService xadesService = new XadesService();
            using (FileStream fs = new FileStream(ruta, FileMode.Open))
            {
                var documento = xadesService.Sign(fs, sp);
                MoverNodoFirma(documento);
                return documento;
            }
        }

        private void AlmacenamientoDocumento(SignatureDocument sd, string ruta, string nombre)
        {
            ruta = $@"{ruta}\{nombre}-Firmado.xml";
            sd.Save(ruta);
        }
        
        public SignatureParameters ParametrosdeFirma()
        {
            SignatureParameters parametros = new SignatureParameters
            {
                SignaturePackaging = SignaturePackaging.INTERNALLY_DETACHED,
                InputMimeType = "text/xml",
                ElementIdToSign = "DatosEmision",
                SignatureMethod = SignatureMethod.RSAwithSHA256,
                DigestMethod = FirmaXadesNet.Crypto.DigestMethod.SHA256
            };
            
            return parametros;
        }
        
        private void MoverNodoFirma(SignatureDocument sd)
        {
            var documento = sd.Document;
            
            var NodoFirma = documento.GetElementsByTagName("ds:Signature")[0];
            NodoFirma.ParentNode.RemoveChild(NodoFirma);

            documento.DocumentElement.AppendChild(NodoFirma);
        }
    }
}
