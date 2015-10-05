using System;
using Microsoft.Owin.Hosting;

namespace Nancy.Server {
    public class Program {

        public void Main(string[] args) {
            var baseAddress = "http://localhost:54541/";

            // Start OWIN host 
            using (WebApp.Start<Startup>(baseAddress)) {
                Console.WriteLine($"Server is running on {baseAddress}, press CTRL+C to stop.");
                Console.ReadLine();
            }
        }
    }
}