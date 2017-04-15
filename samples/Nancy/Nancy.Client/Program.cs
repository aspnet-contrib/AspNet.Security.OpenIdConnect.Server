using System;
using Microsoft.Owin.Hosting;

namespace Nancy.Client
{
    public static class Program
    {
        public static void Main(string[] args)
        {
            const string address = "http://localhost:56765/";

            using (WebApp.Start<Startup>(address))
            {
                Console.WriteLine($"Client is running on {address}, press CTRL+C to stop.");
                Console.ReadLine();
            }
        }
    }
}
