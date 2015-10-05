using System;
using Microsoft.Owin.Hosting;

namespace Nancy.Server {
    public class Program {
        public void Main(string[] args) {
            const string address = "http://localhost:54541/";

            // Start OWIN host 
            using (WebApp.Start<Startup>(address)) {
                Console.WriteLine($"Server is running on {address}, press CTRL+C to stop.");
                Console.ReadLine();
            }
        }
    }
}