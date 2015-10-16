using System;
using Microsoft.Owin.Hosting;

namespace Nancy.Client {

    public class Program {
        public void Main(string[] args) {
            var baseAddress = "http://localhost:56765/";

            // Start OWIN host 
            using (WebApp.Start<Startup>(baseAddress)) {
                Console.WriteLine($"Client is running on {baseAddress}, press CTRL+C to stop.");
                Console.ReadLine();
            }
        }
    }
}