using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

namespace Simple.Models
{
    public class TodoItem : BaseEntity<long>
    {
        [Required]
        public string Name { get; set; }

        [DefaultValue(false)]
        public bool IsComplete { get; set; }
    }
}
