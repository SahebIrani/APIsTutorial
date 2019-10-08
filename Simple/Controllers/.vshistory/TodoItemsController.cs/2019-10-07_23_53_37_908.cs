using System;
using System.Net.Mime;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

using Simple.Data;
using Simple.Models;

namespace Simple.Controllers
{
    [Route("api/[controller]")]
    [Produces(MediaTypeNames.Application.Json)]
    [ApiController]
    [Controller]
    public class TodoItemsController : ControllerBase
    {
        public TodoItemsController(ApplicationDbContext context) =>
            Context = context ?? throw new ArgumentNullException(nameof(context));

        public ApplicationDbContext Context { get; }

        //Examine the GET methods
        //These methods implement two GET endpoints:
        //GET /api/TodoItems
        //GET /api/TodoItems/{id}
        //Test the app by calling the two endpoints from a browser or Postman.For example:
        //https://localhost:5001/api/TodoItems
        //https://localhost:5001/api/TodoItems/1
        //[
        //  {
        //    "id": 1,
        //    "name": "Item1",
        //    "isComplete": false
        //  }
        //]

        //[HttpGet("[controller]/[action]/{id}", Name = "TodoItem")]
        [HttpGet("{id}")] // GET: api/TodoItems/5
        public ActionResult<TodoItem> GetTodoItem(long id) => new TodoItem { Id = id };

        // POST: api/TodoItems
        //[HttpPost("/AddTodoItem")]
        [HttpPost]
        public async Task<ActionResult<TodoItem>> PostTodoItem(TodoItem todoItem, CancellationToken ct = default)
        {
            await Context.TodoItems.AddAsync(todoItem, ct);
            await Context.SaveChangesAsync(ct);

            //The CreatedAtAction method:
            //Returns an HTTP 201 status code if successful.
            return CreatedAtAction(/*"GetTodoItem"*/nameof(GetTodoItem), new { id = todoItem.Id }, todoItem);
        }

        // PUT: api/TodoItems/5
        [HttpPut("{id}")]
        public async Task<IActionResult> PutTodoItem(long id, TodoItem todoItem, CancellationToken ct = default)
        {
            if (id != todoItem.Id) return BadRequest();

            Context.Entry(todoItem).State = EntityState.Modified;

            try
            {
                await Context.SaveChangesAsync();
            }
            catch (DbUpdateConcurrencyException)
            {
                if (!TodoItemExists(id))
                {
                    return NotFound();
                }
                else
                {
                    throw;
                }
            }

            return NoContent();
        }

    }
}
