using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Hosting;
using System;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Text;

class Cliente
{
    static readonly byte[] clave;

    static Cliente()
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
        var datosEncriptados = "";
        // Crear y configurar un host web
        var host = new WebHostBuilder()
            .UseKestrel()
            .Configure(app =>
            {
                app.Run(async context =>
                {
                    // URL del servidor local donde se encuentran los datos
                    string apiUrl = "http://localhost:5213/";

                    try
                    {
                        // Realizar solicitud GET al servidor local
                        HttpWebRequest request = (HttpWebRequest)WebRequest.Create(apiUrl);
                        request.Method = "GET";

                        using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
                        using (Stream stream = response.GetResponseStream())
                        using (StreamReader reader = new StreamReader(stream))
                        {
                            if (response.StatusCode == HttpStatusCode.OK)
                            {
                                // Leer los datos de la respuesta
                                datosEncriptados = reader.ReadToEnd();
                                if (!string.IsNullOrEmpty(datosEncriptados))
                                {
                                    // Procesar los datos como sea necesario
                                    context.Response.Headers.Add("Datos-Recibidos", datosEncriptados);
                                    await context.Response.WriteAsync($"Datos recibidos: {datosEncriptados}");

                                    var cipherSuite = Aes.Create();
                                    cipherSuite.Key = clave;
                                    var subcadenasBytes = new List<byte[]>();
                                    string[] subcadenas = datosEncriptados.Split(new string[] { "^^" }, StringSplitOptions.None);
                                    var idEncriptada = subcadenas[0];
                                    var fechaEncriptada = subcadenas[1];
                                    DateOnly date = DateOnly.ParseExact(fechaEncriptada, "dd/MM/yyyy", null);


                                    await context.Response.WriteAsync($"ID: {idEncriptada}");
                                    await context.Response.WriteAsync($"Fecha: {fechaEncriptada}");


                                    /* byte[] idEncriptadaByte = Encoding.UTF8.GetBytes(idEncriptada);
                                    byte[] fechaEncriptadaByte = Encoding.UTF8.GetBytes(fechaEncriptada);
 
                                    await context.Response.WriteAsync($"ID: {idEncriptadaByte}");
                                    await context.Response.WriteAsync($"Fecha: {fechaEncriptadaByte}");*/
                                    // Generar los hashes de los datos encriptados
                                    /* var hashId = GetSHA256Hash(idEncriptada);
                                    var hashFecha = GetSHA256Hash(fechaEncriptadaByte);
 */
                                    // Formatear fecha actual para que coincida con el formato de fecha encriptada
                                    var fechaActual = DateOnly.FromDateTime(DateTime.Now);
                                    await context.Response.WriteAsync($"Fecha Actual: {fechaActual}");

                                    // Generar el hash de la fecha actual encriptada
                                    //byte[] fechaActualBytes = Encoding.UTF8.GetBytes(fechaActual);

                                    // Generar el hash de la fecha actual encriptada
                                    //var hashFechaActual = GetSHA256Hash(fechaActualBytes);

                                    // Comparar los hashes de las fechas encriptadas
                                    //var comparacion = string.Compare(fechaEncriptada, fechaActual);
                                    var comparacion = date.CompareTo(fechaActual);
                                    await context.Response.WriteAsync($"Comparacion: {comparacion}");
                                    if (comparacion >= 0)
                                    {
                                        Console.WriteLine("Clave activa");
                                    }
                                    else if (comparacion < 0)
                                    {
                                        Console.WriteLine("Clave caducada.");
                                    }
                                }
                                else
                                {
                                    await context.Response.WriteAsync("No se encontraron datos en la respuesta.");
                                }
                            }
                            else
                            {
                                await context.Response.WriteAsync($"Error al obtener datos. Código de estado: {response.StatusCode}");
                            }
                        }
                    }
                    catch (WebException ex)
                    {
                        if (ex.Response != null && ((HttpWebResponse)ex.Response).StatusCode == HttpStatusCode.Forbidden)
                        {
                            await context.Response.WriteAsync("Error: Acceso prohibido (403 Forbidden)");
                        }
                        else
                        {
                            await context.Response.WriteAsync($"Error de red: {ex.Message}");
                        }
                    }
                });
            })
            .Build();

        // Ejecutar el host web
        host.Run();
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
    static bool AreEqual(byte[] a, byte[] b)
    {
        if (a == null || b == null || a.Length != b.Length)
            return false;
        for (int i = 0; i < a.Length; i++)
        {
            if (a[i] != b[i])
                return false;
        }
        return true;
    }

    static string GetSHA256Hash(byte[] input)
    {
        using (var sha256 = SHA256.Create())
        {
            var hashBytes = sha256.ComputeHash(input);
            var stringBuilder = new StringBuilder();
            foreach (var b in hashBytes)
            {
                stringBuilder.Append(b.ToString("x2"));
            }
            return stringBuilder.ToString();
        }
    }
}