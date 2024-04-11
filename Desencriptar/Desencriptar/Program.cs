using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

class Program
{
    static readonly byte[] clave;

    static Program()
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
        var booleano = true;
        var fecha = new DateTime(2024, 4, 11);

        // Encriptar los datos
        var cipherSuite = Aes.Create();
        cipherSuite.Key = clave;

        var idEncriptado = EncryptString(id.ToString(), cipherSuite);
        var booleanoEncriptado = EncryptString(booleano.ToString(), cipherSuite);
        var fechaEncriptada = EncryptString(fecha.ToString("yyyy-MM-dd"), cipherSuite);

        // Generar los hashes de los datos encriptados
        var hashId = GetSHA256Hash(idEncriptado);
        var hashBooleano = GetSHA256Hash(booleanoEncriptado);
        var hashFecha = GetSHA256Hash(fechaEncriptada);

        // Formatear fecha actual para que coincida con el formato de fecha encriptada
        var fechaActual = DateTime.UtcNow.ToString("yyyy-MM-dd");

        // Generar el hash de la fecha actual encriptada
        var hashFechaActual = GetSHA256Hash(EncryptString(fechaActual, cipherSuite));

        // Comparar los hashes de las fechas encriptadas
        var comparacion = string.Compare(hashFecha, hashFechaActual);
        if (comparacion >= 0)
        {
            Console.WriteLine("No esta caducada.");
        }
        else if (comparacion < 0)
        {
            Console.WriteLine("Esta caducada.");
        }
        // Comparar el booleano encriptado
        var booleanoDeseadoEncriptado = EncryptString(true.ToString(), cipherSuite);
        if (AreEqual(booleanoEncriptado, booleanoDeseadoEncriptado))
        {
            Console.WriteLine("El booleano está activado.");
        }
        else
        {
            Console.WriteLine("El booleano está desactivado.");
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
