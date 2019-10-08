namespace Simple.Models
{
    public class TodoItem : BaseEntity<long>
    {
        public string Name { get; set; }
        public bool IsComplete { get; set; }
    }
}
