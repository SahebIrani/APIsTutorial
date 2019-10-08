using System.ComponentModel.DataAnnotations;

namespace Simple.Models
{
    public class TodoItem : BaseEntity<long>
    {
        [Required]
        public string Name { get; set; }
        public bool IsComplete { get; set; }
    }
}
