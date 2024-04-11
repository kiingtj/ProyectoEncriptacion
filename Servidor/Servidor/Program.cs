using System;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Text;

class Servidorr
{
    static readonly byte[] clave;

    static Servidorr()
    {
        // Lee la clave desde un archivo
        string rutaClave = "clave.bin";
        if (File.Exists(rutaClave))
        {
            clave = File.ReadAllBytes(rutaClave);
        }
        else
        {
            // Si la clave no existe, genera una nueva y guárdala en el archivo
            clave = GenerarYGuardarClave(rutaClave);
        }
    }

    static byte[] GenerarYGuardarClave(string rutaClave)
    {
        // Genera una clave aleatoria de 256 bits
        byte[] nuevaClave = new byte[32]; // 256 bits
        using (var rng = new RNGCryptoServiceProvider())
        {
            rng.GetBytes(nuevaClave);
        }

        // Guarda la clave en un archivo
        File.WriteAllBytes(rutaClave, nuevaClave);

        return nuevaClave;
    }

    static void Main()
{
    // Datos a encriptar
    var id = 1;
    var fecha = new DateTime(2029, 4, 18);

    // Encriptar los datos
    var cipherSuite = Aes.Create();
    cipherSuite.Key = clave;

    // Servir los datos
    string apiUrl = "http://localhost:5213/"; // Cambia esto según tu configuración
    HttpListener listener = new HttpListener();
    listener.Prefixes.Add(apiUrl);
    listener.Start();
    Console.WriteLine("Servidor iniciado. Esperando solicitud...");

    while (true)
    {
        HttpListenerContext context = listener.GetContext();
        HttpListenerRequest request = context.Request;
        HttpListenerResponse response = context.Response;

        var idEncriptadoBytes = EncryptString(id.ToString(), cipherSuite);
        var fechaEncriptadaBytes = EncryptString(fecha.ToString("yyyy-MM-dd"), cipherSuite);

        // Convertir los arrays de bytes en cadenas Base64
        var idEncriptado = Convert.ToBase64String(idEncriptadoBytes);
        var fechaEncriptada = Convert.ToBase64String(fechaEncriptadaBytes);

        // Concatenar las cadenas Base64 en una sola cadena JSON
        string json = idEncriptado + "^^" + fechaEncriptada + "^^";

        byte[] buffer = System.Text.Encoding.UTF8.GetBytes(json);
        response.ContentLength64 = buffer.Length;
        Stream output = response.OutputStream;
        output.Write(buffer, 0, buffer.Length);
        output.Close();
    }
}

    static byte[] EncryptString(string input, SymmetricAlgorithm cipherSuite)
    {
        var inputBytes = Encoding.UTF8.GetBytes(input);
        using (var ms = new MemoryStream())
        {
            using (var cs = new CryptoStream(ms, cipherSuite.CreateEncryptor(), CryptoStreamMode.Write))
            {
                cs.Write(inputBytes, 0, inputBytes.Length);
                cs.FlushFinalBlock();
            }
            return ms.ToArray();
        }
    }
}