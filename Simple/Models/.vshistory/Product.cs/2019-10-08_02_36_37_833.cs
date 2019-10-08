using System.ComponentModel.DataAnnotations;

namespace Simple.Models
{
    public class Product
    {
        public int Id { get; set; }

        [Required]
        [JsonPropertyName("name")]
        public string Name { get; set; }

        [Required]
        public string Description { get; set; }
    }
}
