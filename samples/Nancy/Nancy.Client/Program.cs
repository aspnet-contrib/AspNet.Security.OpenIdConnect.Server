using System;
using Microsoft.Owin.Hosting;

namespace Nancy.Client {
    public class Program {
        public void Main(string[] args) {
            const string address = "http://localhost:56765/";

            // Start OWIN host 
            using (WebApp.Start<Startup>(address)) {
                Console.WriteLine($"Client is running on {address}, press CTRL+C to stop.");
                Console.ReadLine();
            }
        }
    }
}