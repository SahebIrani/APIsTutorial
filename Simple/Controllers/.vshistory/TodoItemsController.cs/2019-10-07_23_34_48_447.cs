using System;
using System.Net.Mime;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Mvc;

using Simple.Data;
using Simple.Models;

namespace Simple.Controllers
{
    [ApiController]
    [Produces(MediaTypeNames.Application.Json)]
    [Route("[controller]")]
    public class TodoItemsController : ControllerBase
    {
        public TodoItemsController(ApplicationDbContext context)
        {
            Context = context;
        }

        public ApplicationDbContext Context { get; }


        public IActionResult GetTodoItem(long id)
        {
            throw new NotImplementedException();
        }

        // POST: api/TodoItems
        [HttpPost]
        public async Task<ActionResult<TodoItem>> PostTodoItem(TodoItem todoItem, CancellationToken cancellationToken)
        {
            await Context.TodoItems.AddAsync(todoItem, cancellationToken);
            await Context.SaveChangesAsync(cancellationToken);

            //return CreatedAtAction("GetTodoItem", new { id = todoItem.Id }, todoItem);
            return CreatedAtAction(nameof(GetTodoItem), new { id = todoItem.Id }, todoItem);
        }

    }
}
