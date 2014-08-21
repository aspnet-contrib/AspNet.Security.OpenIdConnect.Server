using System.ComponentModel.DataAnnotations;

namespace Nancy.Server.Models {
    public class Nonce {
        [Key]
        public string NonceID { get; set; }
        public string Ticket { get; set; }
    }
}