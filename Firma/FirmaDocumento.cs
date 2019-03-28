using System.IO;
using FirmaXadesNet;
using FirmaXadesNet.Crypto;
using FirmaXadesNet.Signature;
using FirmaXadesNet.Signature.Parameters;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using System.Text;
using FirmaXadesNet.Validation;

namespace Firma
{
    public static class FirmaDocumento
    {
        /// <summary>
        /// Sign the document, return of this and storage in specific path
        /// </summary>
        /// <param name="certifiedPath">Path were it is stored the certified</param> 
        /// <param name="certifiedPassword">Password of the certified</param>
        /// <param name="node">Node to sign of the document</param>
        /// <param name="DocumentPath">Path of the document were is stored</param>
        /// <param name="pathToStorage">Path were to storage the document xml</param>
        /// <returns>Return a xmlDocument signed and save in the specific route</returns>
        public static XmlDocument SignDocument(string certifiedPath, string certifiedPassword, string nodo, string rutaDocumento, string pathToStorage)
        {
            X509Certificate2 cert = new X509Certificate2(certifiedPath, certifiedPassword, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);

            SignatureParameters parametros = SignatureParameters(nodo);
            var nombredocumento = Path.GetFileNameWithoutExtension(rutaDocumento);

            using (parametros.Signer = new Signer(cert))
            {
                var documento = XadesSigned(parametros, rutaDocumento);
                PathToStorage(documento, pathToStorage, nombredocumento);
                return documento.Document;
            }
        }

        /// <summary>
        /// Sign the document and return of this
        /// </summary>
        /// <param name="certifiedPath">Path were it is stored the certified</param> 
        /// <param name="certifiedPassword">Password of the certified</param>
        /// <param name="node">Node to sign of the document</param>
        /// <param name="DocumentPath">Path of the document were is stored</param> 
        /// <returns>Return a xmlDocument signed</returns>
        public static XmlDocument SignDocument(string certifiedPath, string certifiedPassword, string node, string DocumentPath)
        {
            X509Certificate2 cert = new X509Certificate2(certifiedPath, certifiedPassword, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);

            SignatureParameters parameters = SignatureParameters(node);
            using (parameters.Signer = new Signer(cert))
            {
                return XadesSigned(parameters, DocumentPath).Document;
            }
        }

        /// <summary>
        /// Function that make the signature of the document
        /// </summary>
        /// <param name="sp">Document to sign</param> 
        /// <param name="path">Path were the document is storage</param> 
        /// <returns>Return a signed document</returns>
        private static SignatureDocument XadesSigned(SignatureParameters sp, string path)
        {
            XadesService xadesService = new XadesService();
            using (FileStream fs = new FileStream(path, FileMode.Open))
            {
                var document = xadesService.Sign(fs, sp);
                MoveSignatureNode(document);
                return document;
            }
        }

        /// <summary>
        /// Set the path for save the signed document
        /// </summary>
        /// <param name="sd">Document signed to storage</param> 
        /// <param name="path">Path of the document to store</param> 
        /// <param name="name">Name of the document to store</param> 
        private static void PathToStorage(SignatureDocument sd, string path, string name)
        {
            path = $@"{path}\{name}-Signed.xml";
            sd.Save(path);
        }

        /// <summary>
        /// Required parameters like tipe of document, signature method encryption and node to sign
        /// </summary>
        /// <param name="node">Node to be signed</param> 
        /// <returns></returns>
        private static SignatureParameters SignatureParameters(string node)
        {
            SignatureParameters parameters = new SignatureParameters
            {
                SignaturePackaging = SignaturePackaging.INTERNALLY_DETACHED,
                InputMimeType = "text/xml",
                ElementIdToSign = node,
                SignatureMethod = SignatureMethod.RSAwithSHA256,
                DigestMethod = DigestMethod.SHA256
            };

            return parameters;
        }
        
        /// <summary>
        ///  move the position of the signature node to the end of the document  
        /// </summary>
        /// <param name="sd">Document with the signature to move</param> 
        private static void MoveSignatureNode(SignatureDocument sd)
        {
            var document = sd.Document;
            var SignatureNode = document.GetElementsByTagName("Signature")[0];
            SignatureNode.ParentNode.RemoveChild(SignatureNode);
            document.DocumentElement.AppendChild(SignatureNode);
        }
    }
}
